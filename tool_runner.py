"""Strict adapters for read-only assessment tools; never exposes arbitrary commands.

Every adapter starts its sandboxed subprocess asynchronously (Popen, not a blocking
run) and returns a job descriptor immediately. Callers poll ``job_status`` and can
stop a running job with ``job_cancel``, which is idempotent and terminates the whole
sandboxed process group rather than trusting the tool to honour SIGTERM. Each
execution also gets a best-effort CPU/memory ceiling (cgroup v2 leaf, a user systemd
scope, or POSIX rlimits, in that order); whichever mechanism actually applied - if
any - is reported back on the job rather than assumed.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET

try:
    import resource
except ImportError:  # pragma: no cover - POSIX-only module; this project targets Linux
    resource = None  # type: ignore[assignment]


TERMINATE_GRACE_SECONDS = 2.0
DEFAULT_CPU_PERCENT = 100
DEFAULT_CPU_SECONDS = 120
DEFAULT_MEMORY_BYTES = 512 * 1024 * 1024
MAX_RETAINED_JOBS = 200
_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
# nmap's optional script_category argument is restricted to this fixed allowlist -
# never a raw script name, and never a category (vuln, auth, exploit, intrusive,
# dos, external) that probes for or acts on a weakness rather than just
# enumerating what's there. Matches docs/platform-roadmap.md's tool-runner safety
# contract: "Tools or flags that exploit, alter, persist on, evade, or disrupt a
# target remain disabled unless a future approval policy explicitly permits that
# exact operation."
NMAP_SAFE_SCRIPT_CATEGORIES = ("default", "discovery", "safe")


class ToolRunner:
    MANIFESTS = {
        "tool.nmap.services": {
            "executable": "nmap", "risk_class": "discovery", "timeout_seconds": 120,
            "max_targets": 32, "max_ports": 128, "output": "nmap-services/v1",
            "flags": ["connect-scan", "no-os-detection", "safe-script-categories-only"],
            "argument_schema": {"hosts": "ipv4[1..32]", "ports": "integer[1..65535][1..128]",
                                 "script_category": "enum[default,discovery,safe]?"},
            "isolation": "bubblewrap-ro-root-v1",
            "resource_limits": {"cpu_percent": DEFAULT_CPU_PERCENT, "memory_bytes": DEFAULT_MEMORY_BYTES},
        },
        "tool.masscan.services": {
            "executable": "masscan", "risk_class": "discovery", "timeout_seconds": 120,
            "max_targets": 32, "max_ports": 128, "output": "nmap-services/v1",
            "flags": ["fixed-rate", "no-banners", "syn-scan"],
            "argument_schema": {"hosts": "ipv4[1..32]", "ports": "integer[1..65535][1..128]"},
            "isolation": "bubblewrap-ro-root-v1",
            "resource_limits": {"cpu_percent": DEFAULT_CPU_PERCENT, "memory_bytes": DEFAULT_MEMORY_BYTES},
            # masscan sends raw SYN packets rather than using the kernel's TCP stack
            # (there is no masscan equivalent of nmap's -sT connect scan), so unlike
            # every other adapter here it needs CAP_NET_RAW at the binary itself:
            # `sudo setcap cap_net_raw,cap_net_admin+eip $(command -v masscan)`.
            # Bubblewrap isolation here (_sandbox_command) doesn't unshare the user
            # namespace, so a file capability set on the host binary carries through
            # unchanged; nothing in this codebase applies or checks it, and a missing
            # capability surfaces as an ordinary failed-job stderr message, not a
            # distinct error code. --rate is intentionally fixed, not an argument:
            # masscan's entire differentiator is scan speed/scale, and this adapter
            # deliberately declines to expose that knob.
            "notes": "requires cap_net_raw,cap_net_admin on the masscan binary",
        },
        "tool.arpscan.sweep": {
            "executable": "arp-scan", "risk_class": "discovery", "timeout_seconds": 30,
            "output": "arp-scan/v1", "flags": ["local-segment-only"],
            "argument_schema": {"interface": "enum[discovered]"},
            "isolation": "bubblewrap-ro-root-v1",
            "resource_limits": {"cpu_percent": DEFAULT_CPU_PERCENT, "memory_bytes": DEFAULT_MEMORY_BYTES},
            # Also needs CAP_NET_RAW on the binary (raw ARP frames), same caveat as
            # masscan above. No host/port targeting at all: arp-scan can only ever
            # see its own attached L2 segment regardless of arguments, so there is no
            # scope-containment question the way there is for nmap/masscan.
            "notes": "requires cap_net_raw on the arp-scan binary",
        },
        "tool.dns.lookup": {
            "executable": "dig", "risk_class": "discovery", "timeout_seconds": 20,
            "max_names": 8, "output": "dns-lookup/v1",
            "flags": ["single-try", "bounded-timeout", "no-recursive-side-effects"],
            "argument_schema": {"names": "hostname[1..8]",
                                 "record_type": "enum[A,AAAA,MX,TXT,NS,CNAME,SOA]"},
            "isolation": "bubblewrap-ro-root-v1",
            "resource_limits": {"cpu_percent": DEFAULT_CPU_PERCENT, "memory_bytes": DEFAULT_MEMORY_BYTES},
        },
        "tool.tcpdump.capture": {
            "executable": "tcpdump", "risk_class": "discovery", "timeout_seconds": 35,
            "max_packets": 100, "output": "tcpdump-capture/v1",
            "flags": ["header-only-snaplen", "no-name-resolution", "count-bounded", "no-arbitrary-filter"],
            "argument_schema": {"interface": "enum[discovered]", "count": "integer[1..100]",
                                 "host": "ipv4?", "port": "integer[1..65535]?"},
            "isolation": "bubblewrap-ro-root-v1",
            "resource_limits": {"cpu_percent": DEFAULT_CPU_PERCENT, "memory_bytes": DEFAULT_MEMORY_BYTES},
        },
    }

    def __init__(self, signing_key: bytes | None = None, cgroup_root: str = "/sys/fs/cgroup") -> None:
        self.signing_key = signing_key
        self.cgroup_root = cgroup_root
        self.jobs: dict[str, dict] = {}
        self.jobs_lock = threading.Lock()

    def manifest(self, capability: str) -> dict:
        source = self.MANIFESTS[capability]
        executable = shutil.which(source["executable"])
        document = {**source, "capability": capability, "executable_path": executable or "",
                    "executable_sha256": self._file_digest(executable) if executable else ""}
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        document["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
        if self.signing_key is not None:
            document["manifest_tag"] = hmac.new(self.signing_key, canonical, hashlib.sha256).hexdigest()
        return document

    @staticmethod
    def _file_digest(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def available(self) -> dict:
        sandbox = shutil.which("bwrap") is not None
        return {capability: {**self.manifest(capability),
                             "available": sandbox and shutil.which(manifest["executable"]) is not None}
                for capability, manifest in self.MANIFESTS.items()}

    # ------------------------------------------------------------------
    # Job registry: async execution, status polling, and cancellation.
    # ------------------------------------------------------------------

    @staticmethod
    def _now_ms() -> int:
        return int(time.time() * 1000)

    @staticmethod
    def _new_job_id(kind: str) -> str:
        return f"tool-{kind}-{uuid.uuid4().hex[:12]}"

    def _prune_jobs_locked(self) -> None:
        # Bound memory for a long-running node: never drop a running job, only
        # the oldest finished ones once the registry grows past the cap.
        if len(self.jobs) <= MAX_RETAINED_JOBS:
            return
        finished = sorted(
            (job for job in self.jobs.values() if job["job_status"] != "running"),
            key=lambda job: job.get("finished_at_ms") or 0,
        )
        for job in finished[: len(self.jobs) - MAX_RETAINED_JOBS]:
            self.jobs.pop(job["job_id"], None)

    @staticmethod
    def _public_job(job: dict) -> dict:
        with job["lock"]:
            return {
                "job_id": job["job_id"], "capability": job["capability"],
                "job_status": job["job_status"], "result": job.get("result"),
                "error": job.get("error", ""),
                "resource_ceiling": dict(job.get("resource_ceiling", {"mechanism": "none", "applied": False})),
                "started_at_ms": job.get("started_at_ms"), "finished_at_ms": job.get("finished_at_ms"),
            }

    def job_status(self, arguments: dict) -> dict:
        job_id = str(arguments.get("job_id", ""))
        with self.jobs_lock:
            job = self.jobs.get(job_id)
        if job is None:
            return {"job_id": job_id, "capability": "", "job_status": "not_found",
                     "result": None, "error": "unknown job_id",
                     "resource_ceiling": {"mechanism": "none", "applied": False},
                     "started_at_ms": None, "finished_at_ms": None}
        return self._public_job(job)

    def job_cancel(self, arguments: dict) -> dict:
        # Idempotent: cancelling a job that is not running (or does not exist)
        # is still a successful "ok" no-op, matching the discovery-scan cancel
        # convention (Node.cancel_network_scan).
        job_id = str(arguments.get("job_id", ""))
        with self.jobs_lock:
            job = self.jobs.get(job_id)
        if job is None:
            return {"ok": True, "job_id": job_id, "job_status": "not_found", "cancelled": False}
        with job["lock"]:
            process = job.get("process")
            running = job["job_status"] == "running"
            job["cancel_requested"] = True
        if not running or process is None:
            response = self._public_job(job)
            response.update(ok=True, cancelled=False)
            return response
        self._terminate_process_group(process)
        # Give the worker thread a brief moment to observe the exit and settle
        # job_status to "cancelled" before we report back.
        deadline = time.monotonic() + TERMINATE_GRACE_SECONDS + 1.0
        while time.monotonic() < deadline:
            with job["lock"]:
                if job["job_status"] != "running":
                    break
            time.sleep(0.02)
        response = self._public_job(job)
        response.update(ok=True, cancelled=True)
        return response

    @staticmethod
    def _terminate_process_group(process: subprocess.Popen, grace_seconds: float | None = None) -> None:
        """Best-effort teardown of the sandboxed subprocess.

        bwrap is started with start_new_session=True, so it leads its own
        process group; signalling that group reaches bwrap and anything it
        spawned even if the wrapped tool ignores SIGTERM. bwrap's own
        --unshare-pid/--die-with-parent sandbox also tears its pid-namespace
        children down once its supervising process is gone, so this is
        belt-and-braces rather than the only mechanism. SIGTERM is escalated
        to SIGKILL only if the process is still alive after the grace period.
        """
        if grace_seconds is None:
            grace_seconds = TERMINATE_GRACE_SECONDS
        try:
            pgid = os.getpgid(process.pid)
        except (ProcessLookupError, OSError):
            return
        try:
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            return
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return
            time.sleep(0.05)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    # ------------------------------------------------------------------
    # Best-effort CPU/memory ceilings.
    # ------------------------------------------------------------------

    def _select_resource_ceiling(self, job_id: str, cpu_percent: int = DEFAULT_CPU_PERCENT,
                                  memory_bytes: int = DEFAULT_MEMORY_BYTES) -> dict:
        """Never raises. Tries a cgroup v2 leaf, then a user systemd scope,
        then POSIX rlimits as an almost-always-available last resort. Returns
        a dict describing exactly what was selected so callers/tests never
        have to guess: {"mechanism", "command_prefix", "preexec_fn", "cgroup_leaf"}.
        "mechanism" is "none" only when nothing at all could be applied."""
        leaf = self._create_cgroup_leaf(job_id, cpu_percent, memory_bytes)
        if leaf is not None:
            return {"mechanism": "cgroup-v2", "command_prefix": [], "preexec_fn": None, "cgroup_leaf": leaf}
        systemd_run = shutil.which("systemd-run")
        if systemd_run is not None and os.environ.get("XDG_RUNTIME_DIR"):
            prefix = [systemd_run, "--user", "--scope", "--quiet",
                      "-p", f"CPUQuota={cpu_percent}%", "-p", f"MemoryMax={memory_bytes}", "--"]
            return {"mechanism": "systemd-run", "command_prefix": prefix, "preexec_fn": None, "cgroup_leaf": None}
        preexec = self._rlimit_preexec(DEFAULT_CPU_SECONDS, memory_bytes)
        if preexec is not None:
            return {"mechanism": "rlimit", "command_prefix": [], "preexec_fn": preexec, "cgroup_leaf": None}
        return {"mechanism": "none", "command_prefix": [], "preexec_fn": None, "cgroup_leaf": None}

    def _create_cgroup_leaf(self, job_id: str, cpu_percent: int, memory_bytes: int) -> str | None:
        controllers_path = os.path.join(self.cgroup_root, "cgroup.controllers")
        try:
            with open(controllers_path, encoding="utf-8") as handle:
                controllers = handle.read().split()
        except OSError:
            return None
        if "cpu" not in controllers or "memory" not in controllers:
            return None
        group_dir = os.path.join(self.cgroup_root, "reconclave-tools")
        leaf = os.path.join(group_dir, job_id)
        try:
            os.makedirs(leaf, exist_ok=True)
            subtree_control = os.path.join(self.cgroup_root, "cgroup.subtree_control")
            try:
                with open(subtree_control, "a", encoding="utf-8") as handle:
                    handle.write("+cpu +memory")
            except OSError:
                pass  # controllers may already be delegated; the leaf writes below prove it either way
            period_us = 100000
            quota_us = max(1000, int(period_us * cpu_percent / 100))
            with open(os.path.join(leaf, "cpu.max"), "w", encoding="utf-8") as handle:
                handle.write(f"{quota_us} {period_us}")
            with open(os.path.join(leaf, "memory.max"), "w", encoding="utf-8") as handle:
                handle.write(str(memory_bytes))
        except OSError:
            return None
        return leaf

    @staticmethod
    def _write_cgroup_pid(leaf: str, pid: int) -> bool:
        try:
            with open(os.path.join(leaf, "cgroup.procs"), "w", encoding="utf-8") as handle:
                handle.write(str(pid))
            return True
        except OSError:
            return False

    @staticmethod
    def _rlimit_preexec(cpu_seconds: int, memory_bytes: int):
        if resource is None:
            return None

        def _apply() -> None:
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            except (ValueError, OSError):
                pass
            try:
                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            except (ValueError, OSError):
                pass

        return _apply

    # ------------------------------------------------------------------
    # Job execution.
    # ------------------------------------------------------------------

    def _start_job(self, job_id: str, capability: str, command: list[str], timeout: int,
                    parse_fn, ceiling: dict) -> None:
        job = {
            "job_id": job_id, "capability": capability, "job_status": "running",
            "result": None, "error": "", "process": None, "pid": None,
            "cancel_requested": False, "started_at_ms": self._now_ms(), "finished_at_ms": None,
            "resource_ceiling": {"mechanism": ceiling["mechanism"], "applied": ceiling["mechanism"] != "none"},
            "lock": threading.Lock(),
        }
        with self.jobs_lock:
            self.jobs[job_id] = job
            self._prune_jobs_locked()
        threading.Thread(target=self._run_job, args=(job, command, timeout, parse_fn, ceiling),
                         daemon=True, name=f"tool-job-{job_id}").start()

    def _run_job(self, job: dict, command: list[str], timeout: int, parse_fn, ceiling: dict) -> None:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       stdin=subprocess.DEVNULL, text=True, start_new_session=True,
                                       preexec_fn=ceiling.get("preexec_fn"))
        except OSError as error:
            with job["lock"]:
                job["job_status"] = "failed"
                job["error"] = str(error)[:500]
                job["finished_at_ms"] = self._now_ms()
            return
        with job["lock"]:
            job["process"] = process
            job["pid"] = process.pid
        if ceiling["mechanism"] == "cgroup-v2" and ceiling.get("cgroup_leaf"):
            applied = self._write_cgroup_pid(ceiling["cgroup_leaf"], process.pid)
            with job["lock"]:
                job["resource_ceiling"] = {"mechanism": "cgroup-v2" if applied else "none", "applied": applied}
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate_process_group(process)
            try:
                stdout, stderr = process.communicate(timeout=TERMINATE_GRACE_SECONDS + 1.0)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", ""
        returncode = process.returncode
        with job["lock"]:
            cancelled = job["cancel_requested"]
            job["process"] = None
            job["pid"] = None
            job["finished_at_ms"] = self._now_ms()
            if cancelled:
                job["job_status"] = "cancelled"
                job["error"] = "cancelled by operator"
            elif timed_out:
                job["job_status"] = "failed"
                job["error"] = f"{job['capability']} timed out after {timeout}s"
            elif returncode != 0:
                job["job_status"] = "failed"
                job["error"] = (stderr or f"{job['capability']} failed")[:500]
            else:
                try:
                    job["result"] = parse_fn(stdout)
                    job["job_status"] = "complete"
                except Exception as error:  # keep the job's failure visible instead of losing the worker
                    job["job_status"] = "failed"
                    job["error"] = f"failed to parse output: {error}"[:500]

    @staticmethod
    def _sandbox_command(sandbox: str, tool_command: list[str]) -> list[str]:
        return [sandbox, "--die-with-parent", "--new-session", "--unshare-pid",
                "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
                "--tmpfs", "/tmp", "--", *tool_command]

    # ------------------------------------------------------------------
    # tool.nmap.services
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_hosts_and_ports(arguments: dict, max_targets: int, max_ports: int) -> tuple[list[str], list[int]]:
        """Shared bounds/type checking for the two IP/port-targeted scan adapters
        (nmap, masscan) - kept in one place so both stay bound to the same rules
        rather than drifting apart."""
        raw_targets = arguments.get("hosts", [])
        raw_ports = arguments.get("ports", [])
        if not isinstance(raw_targets, list) or not 1 <= len(raw_targets) <= max_targets:
            raise ValueError(f"hosts must contain 1-{max_targets} IP addresses")
        if not isinstance(raw_ports, list) or not 1 <= len(raw_ports) <= max_ports:
            raise ValueError(f"ports must contain 1-{max_ports} values")
        targets = [str(ipaddress.ip_address(str(value))) for value in dict.fromkeys(raw_targets)]
        ports = sorted({int(value) for value in raw_ports})
        if any(not 1 <= port <= 65535 for port in ports):
            raise ValueError("ports must be between 1 and 65535")
        return targets, ports

    def nmap_services(self, arguments: dict) -> dict:
        manifest = self.MANIFESTS["tool.nmap.services"]
        executable = shutil.which(manifest["executable"])
        if executable is None:
            raise RuntimeError("nmap is not installed")
        targets, ports = self._validate_hosts_and_ports(arguments, manifest["max_targets"], manifest["max_ports"])
        script_category = arguments.get("script_category")
        script_args: list[str] = []
        if script_category is not None:
            script_category = str(script_category)
            if script_category not in NMAP_SAFE_SCRIPT_CATEGORIES:
                raise ValueError(f"script_category must be one of {NMAP_SAFE_SCRIPT_CATEGORIES}")
            script_args = ["--script", script_category]
        sandbox = shutil.which("bwrap")
        if sandbox is None:
            raise RuntimeError("bubblewrap isolation is not installed")
        tool_command = [executable, "-n", "-Pn", "-sT", "--max-retries", "1", "--host-timeout", "30s",
                   "-p", ",".join(map(str, ports)), *script_args, "-oX", "-", "--", *targets]
        command = self._sandbox_command(sandbox, tool_command)
        job_id = self._new_job_id("nmap")
        limits = manifest["resource_limits"]
        ceiling = self._select_resource_ceiling(job_id, limits["cpu_percent"], limits["memory_bytes"])
        self._start_job(job_id, "tool.nmap.services", ceiling["command_prefix"] + command,
                        manifest["timeout_seconds"],
                        lambda stdout: self._parse_nmap_xml(stdout, targets, ports, manifest), ceiling)
        return self.job_status({"job_id": job_id})

    @staticmethod
    def _parse_nmap_xml(stdout: str, targets: list[str], ports: list[int], manifest: dict,
                        tool_name: str = "nmap") -> dict:
        # Shared by tool.nmap.services and tool.masscan.services: masscan's -oX
        # output is nmap-compatible XML (host/address/ports/port/state elements),
        # and without --banners it has no <service> element either, matching
        # nmap's own "unknown" fallback below - both adapters land in the same
        # nmap-services/v1 result shape so vulnerability_analysis.extract_observations
        # needs no tool-specific branch.
        root = ET.fromstring(stdout)
        hosts = []
        for host in root.findall("host"):
            address = host.find("address")
            if address is None or address.get("addr") not in targets:
                continue
            services = []
            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")
                if state is not None and state.get("state") == "open":
                    services.append({"port": int(port.get("portid", "0")),
                                     "protocol": port.get("protocol", "tcp"),
                                     "service": service.get("name", "unknown") if service is not None else "unknown"})
            hosts.append({"address": address.get("addr"), "services": services})
        return {"schema": manifest["output"], "tool": tool_name, "hosts": hosts,
                "targets": targets, "ports": ports}

    # ------------------------------------------------------------------
    # tool.masscan.services
    # ------------------------------------------------------------------

    def masscan_services(self, arguments: dict) -> dict:
        manifest = self.MANIFESTS["tool.masscan.services"]
        executable = shutil.which(manifest["executable"])
        if executable is None:
            raise RuntimeError("masscan is not installed")
        targets, ports = self._validate_hosts_and_ports(arguments, manifest["max_targets"], manifest["max_ports"])
        sandbox = shutil.which("bwrap")
        if sandbox is None:
            raise RuntimeError("bubblewrap isolation is not installed")
        # --rate is fixed (see the manifest's "notes"); no --banners, so this stays
        # a pure port-state scan like nmap's -sT above (no probe/banner traffic).
        tool_command = [executable, "--rate", "100", "-p", ",".join(map(str, ports)),
                        "-oX", "-", "--wait", "2", *targets]
        command = self._sandbox_command(sandbox, tool_command)
        job_id = self._new_job_id("masscan")
        limits = manifest["resource_limits"]
        ceiling = self._select_resource_ceiling(job_id, limits["cpu_percent"], limits["memory_bytes"])
        self._start_job(job_id, "tool.masscan.services", ceiling["command_prefix"] + command,
                        manifest["timeout_seconds"],
                        lambda stdout: self._parse_nmap_xml(stdout, targets, ports, manifest, "masscan"), ceiling)
        return self.job_status({"job_id": job_id})

    # ------------------------------------------------------------------
    # tool.dns.lookup
    # ------------------------------------------------------------------

    def dns_lookup(self, arguments: dict) -> dict:
        manifest = self.MANIFESTS["tool.dns.lookup"]
        executable = shutil.which(manifest["executable"])
        if executable is None:
            raise RuntimeError("dig is not installed")
        raw_names = arguments.get("names", [])
        if not isinstance(raw_names, list) or not 1 <= len(raw_names) <= manifest["max_names"]:
            raise ValueError(f"names must contain 1-{manifest['max_names']} hostnames")
        names = list(dict.fromkeys(str(value) for value in raw_names))
        for name in names:
            labels = name.rstrip(".").split(".")
            if len(name) > 253 or not labels or not all(_HOSTNAME_LABEL.match(label) for label in labels):
                raise ValueError(f"invalid hostname: {name!r}")
        record_type = str(arguments.get("record_type", "A")).upper()
        allowed_types = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")
        if record_type not in allowed_types:
            raise ValueError(f"record_type must be one of {allowed_types}")
        sandbox = shutil.which("bwrap")
        if sandbox is None:
            raise RuntimeError("bubblewrap isolation is not installed")
        tool_command = [executable, "+noall", "+answer", "+time=2", "+tries=1", record_type, *names]
        command = self._sandbox_command(sandbox, tool_command)
        job_id = self._new_job_id("dns")
        limits = manifest["resource_limits"]
        ceiling = self._select_resource_ceiling(job_id, limits["cpu_percent"], limits["memory_bytes"])
        self._start_job(job_id, "tool.dns.lookup", ceiling["command_prefix"] + command,
                        manifest["timeout_seconds"],
                        lambda stdout: self._parse_dig_answer(stdout, names, record_type, manifest), ceiling)
        return self.job_status({"job_id": job_id})

    @staticmethod
    def _parse_dig_answer(stdout: str, names: list[str], record_type: str, manifest: dict) -> dict:
        answers = []
        for line in stdout.splitlines():
            if not line.strip() or line.startswith(";"):
                continue
            fields = line.split(None, 4)
            if len(fields) < 5:
                continue
            name, ttl, dns_class, rtype, value = fields
            answers.append({"name": name, "ttl": int(ttl) if ttl.isdigit() else 0,
                            "class": dns_class, "type": rtype, "value": value.strip()})
        return {"schema": manifest["output"], "tool": "dig", "record_type": record_type,
                "names": names, "answers": answers}

    # ------------------------------------------------------------------
    # tool.tcpdump.capture
    # ------------------------------------------------------------------

    def tcpdump_capture(self, arguments: dict) -> dict:
        manifest = self.MANIFESTS["tool.tcpdump.capture"]
        executable = shutil.which(manifest["executable"])
        if executable is None:
            raise RuntimeError("tcpdump is not installed")
        interfaces = {name for _, name in socket.if_nameindex()}
        interface = str(arguments.get("interface", ""))
        if interface not in interfaces:
            raise ValueError(f"interface must be one of the host's discovered interfaces: {sorted(interfaces)}")
        raw_count = arguments.get("count", 20)
        if not isinstance(raw_count, int) or isinstance(raw_count, bool) or not 1 <= raw_count <= manifest["max_packets"]:
            raise ValueError(f"count must be an integer between 1 and {manifest['max_packets']}")
        filter_terms: list[str] = []
        host = arguments.get("host")
        if host is not None:
            filter_terms += ["host", str(ipaddress.ip_address(str(host)))]
        port = arguments.get("port")
        if port is not None:
            port = int(port)
            if not 1 <= port <= 65535:
                raise ValueError("port must be between 1 and 65535")
            filter_terms += (["and", "port", str(port)] if filter_terms else ["port", str(port)])
        sandbox = shutil.which("bwrap")
        if sandbox is None:
            raise RuntimeError("bubblewrap isolation is not installed")
        tool_command = [executable, "-nn", "-tttt", "-q", "-l", "-s", "96",
                        "-c", str(raw_count), "-i", interface, *filter_terms]
        command = self._sandbox_command(sandbox, tool_command)
        job_id = self._new_job_id("tcpdump")
        limits = manifest["resource_limits"]
        ceiling = self._select_resource_ceiling(job_id, limits["cpu_percent"], limits["memory_bytes"])
        self._start_job(job_id, "tool.tcpdump.capture", ceiling["command_prefix"] + command,
                        manifest["timeout_seconds"],
                        lambda stdout: self._parse_tcpdump_lines(stdout, interface, raw_count, manifest), ceiling)
        return self.job_status({"job_id": job_id})

    @staticmethod
    def _parse_tcpdump_lines(stdout: str, interface: str, requested_count: int, manifest: dict) -> dict:
        # "-tttt" prefixes each line with "YYYY-MM-DD HH:MM:SS.ffffff "; "-q"
        # keeps the rest to one summary line per packet, e.g.
        # "2026-09-04 22:31:05.123456 IP 192.168.1.10.443 > 192.168.1.20.51234: tcp 0"
        packets = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 2)
            if len(parts) < 3:
                continue
            packets.append({"timestamp": f"{parts[0]} {parts[1]}", "summary": parts[2]})
        return {"schema": manifest["output"], "tool": "tcpdump", "interface": interface,
                "requested_count": requested_count, "packets": packets}

    # ------------------------------------------------------------------
    # tool.arpscan.sweep
    # ------------------------------------------------------------------

    def arpscan_sweep(self, arguments: dict) -> dict:
        manifest = self.MANIFESTS["tool.arpscan.sweep"]
        executable = shutil.which(manifest["executable"])
        if executable is None:
            raise RuntimeError("arp-scan is not installed")
        interfaces = {name for _, name in socket.if_nameindex()}
        interface = str(arguments.get("interface", ""))
        if interface not in interfaces:
            raise ValueError(f"interface must be one of the host's discovered interfaces: {sorted(interfaces)}")
        sandbox = shutil.which("bwrap")
        if sandbox is None:
            raise RuntimeError("bubblewrap isolation is not installed")
        # --localnet sweeps the interface's own attached IPv4 subnet - the only
        # targeting mode this adapter exposes, since arp-scan cannot see past its
        # own L2 segment regardless of arguments. --plain drops the summary/banner
        # lines so stdout is exactly one "ip\tmac\tvendor" line per responding host.
        tool_command = [executable, "--interface", interface, "--localnet", "--plain", "--retry", "1"]
        command = self._sandbox_command(sandbox, tool_command)
        job_id = self._new_job_id("arpscan")
        limits = manifest["resource_limits"]
        ceiling = self._select_resource_ceiling(job_id, limits["cpu_percent"], limits["memory_bytes"])
        self._start_job(job_id, "tool.arpscan.sweep", ceiling["command_prefix"] + command,
                        manifest["timeout_seconds"],
                        lambda stdout: self._parse_arpscan_lines(stdout, interface, manifest), ceiling)
        return self.job_status({"job_id": job_id})

    @staticmethod
    def _parse_arpscan_lines(stdout: str, interface: str, manifest: dict) -> dict:
        # --plain output is one line per responding host:
        # "192.168.1.1\t00:11:22:33:44:55\tVendor Name Inc."
        # The vendor field is free text from arp-scan's OUI database and may be
        # empty (unknown OUI) or absent entirely for some entries.
        hosts = []
        for line in stdout.splitlines():
            fields = line.rstrip("\n").split("\t")
            if len(fields) < 2:
                continue
            address, mac = fields[0].strip(), fields[1].strip()
            if not address or not mac:
                continue
            vendor = fields[2].strip() if len(fields) > 2 else ""
            hosts.append({"address": address, "mac": mac, "vendor": vendor})
        return {"schema": manifest["output"], "tool": "arp-scan", "interface": interface, "hosts": hosts}
