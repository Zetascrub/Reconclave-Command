from __future__ import annotations

import pathlib
import tempfile
import unittest

from manual_peers import ManualPeers


class ManualPeersTests(unittest.TestCase):
    def test_saved_targets_survive_restart_and_can_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "peers.json"
            peers = ManualPeers(path)
            self.assertEqual(peers.add("192.168.8.136", 8787), ("192.168.8.136", 8787))
            self.assertEqual(ManualPeers(path).list(), [{"address": "192.168.8.136", "port": 8787}])
            peers.remove("192.168.8.136", 8787)
            self.assertEqual(ManualPeers(path).list(), [])

    def test_rejects_public_or_malformed_targets(self) -> None:
        for address, port in [("8.8.8.8", 8787), ("192.168.8.136", 0),
                              ("192.168.8.136", 65536), ("example.com", 8787)]:
            with self.subTest(address=address, port=port):
                with self.assertRaises(ValueError):
                    ManualPeers.validate(address, port)


if __name__ == "__main__":
    unittest.main()
