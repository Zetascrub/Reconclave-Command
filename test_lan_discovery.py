from __future__ import annotations

import json
import unittest
from unittest import mock

import lan_discovery


class LanDiscoveryTests(unittest.TestCase):
    def test_scan_uses_only_active_desktop_subnet_and_caps_broad_network(self):
        interfaces = [
            {"ifname": "br-test", "operstate": "UP", "addr_info": [{"local": "172.18.0.1", "prefixlen": 16}]},
            {"ifname": "eth0", "operstate": "UP", "addr_info": [{"local": "192.168.8.10", "prefixlen": 16}]},
        ]
        with mock.patch.object(lan_discovery.subprocess, "check_output", return_value=json.dumps(interfaces).encode()):
            network = lan_discovery.local_scan_network("192.168.8.10")
        self.assertEqual(str(network), "192.168.8.0/24")

    def test_public_or_unattached_address_is_not_scanned(self):
        with mock.patch.object(lan_discovery.subprocess, "check_output", return_value=b"[]"):
            self.assertIsNone(lan_discovery.local_scan_network("192.168.8.10"))
            self.assertIsNone(lan_discovery.local_scan_network("8.8.8.8"))
