"""Saved unicast discovery targets for nodes whose mDNS cannot cross the LAN."""

from __future__ import annotations

import ipaddress
import json
import pathlib
import threading


class ManualPeers:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self.lock = threading.RLock()
        data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []
        if not isinstance(data, list):
            raise ValueError("manual peer store must be a list")
        self.targets: set[tuple[str, int]] = set()
        for item in data:
            self.targets.add(self.validate(item["address"], item["port"]))

    @staticmethod
    def validate(address: object, port: object) -> tuple[str, int]:
        ip = ipaddress.ip_address(str(address))
        if ip.version != 4 or not (ip.is_private or ip.is_link_local):
            raise ValueError("device address must be a private IPv4 address")
        if isinstance(port, bool) or not str(port).isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("device port must be between 1 and 65535")
        return str(ip), int(port)

    def list(self) -> list[dict]:
        with self.lock:
            return [{"address": address, "port": port}
                    for address, port in sorted(self.targets)]

    def add(self, address: object, port: object) -> tuple[str, int]:
        target = self.validate(address, port)
        with self.lock:
            if len(self.targets) >= 32 and target not in self.targets:
                raise ValueError("at most 32 manual devices can be saved")
            self.targets.add(target)
            self._save()
        return target

    def remove(self, address: object, port: object) -> tuple[str, int]:
        target = self.validate(address, port)
        with self.lock:
            self.targets.discard(target)
            self._save()
        return target

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(self.list(), indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)
