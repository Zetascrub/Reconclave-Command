"""Bounded, local-subnet fallback for Reconclave's mDNS discovery."""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

DISCOVERY_PORTS = (80, 8765, 8766, 8787)


def local_scan_network(address: str) -> ipaddress.IPv4Network | None:
    """Only scan the desktop's active private LAN, capped at one /24."""
    try:
        target = ipaddress.IPv4Address(address)
        if not target.is_private:
            return None
        interfaces = json.loads(subprocess.check_output(
            ["ip", "-json", "-4", "addr", "show", "scope", "global"],
            timeout=2, stderr=subprocess.DEVNULL))
        for interface in interfaces:
            if interface.get("operstate") != "UP" or interface.get("ifname", "").startswith(("docker", "br-", "veth")):
                continue
            for info in interface.get("addr_info", []):
                if info.get("local") != address:
                    continue
                prefix = max(24, int(info["prefixlen"]))
                return ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        pass
    return None


def scan_lan(address: str, refresh: Callable[[str, int], bool],
             stopping: Callable[[], bool] = lambda: False) -> int:
    network = local_scan_network(address)
    if network is None:
        return 0

    def probe(host: str, port: int) -> bool:
        if stopping():
            return False
        try:
            with socket.create_connection((host, port), timeout=0.18):
                pass
        except OSError:
            return False
        return refresh(host, port)

    found = 0
    with ThreadPoolExecutor(max_workers=48, thread_name_prefix="reconclave-lan") as pool:
        futures = [pool.submit(probe, str(host), port)
                   for host in network.hosts() if str(host) != address
                   for port in DISCOVERY_PORTS]
        for future in as_completed(futures):
            if future.result():
                found += 1
    return found
