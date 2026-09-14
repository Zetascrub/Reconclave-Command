"""Append-only AES-GCM evidence spool with per-record authenticated encryption."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptedSpool:
    def __init__(self, directory: str, passphrase: str = "", node_id: str = "", *,
                 key: bytes | None = None) -> None:
        """`key`, when given, is used directly instead of deriving one from `passphrase`.

        This is what lets this same reader/format decode an ESP32 device's own spool
        (poe-p4's NVS outbox blob, cardputer-adv's SD evidence log): those devices are
        provisioned with an already-random 32-byte RC_STORAGE_KEY (tools/provision_fleet.py)
        used as the AES key directly, the same way provisioned peer/link keys are used
        directly rather than re-derived from a typed passphrase.
        """
        self.directory = pathlib.Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if key is not None:
            if len(key) != 32:
                raise ValueError("a raw spool key must be exactly 32 bytes")
            self.key = key
        else:
            self.key = hashlib.sha256(("reconclave-spool-v1|" + passphrase).encode()).digest()
        self.node_id = node_id

    def append(self, record: dict, day: str) -> pathlib.Path:
        path = self.directory / f"evidence-{day}.rcspool"
        nonce = os.urandom(12)
        aad = f"reconclave-spool/v1|{self.node_id}".encode()
        plaintext = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, aad)
        frame = {"v": 1, "node": self.node_id,
                 "nonce": base64.b64encode(nonce).decode(),
                 "ciphertext": base64.b64encode(ciphertext).decode()}
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as output:
            output.write(json.dumps(frame, separators=(",", ":")) + "\n")
            output.flush()
            os.fsync(output.fileno())
        return path

    def read(self, path: pathlib.Path) -> list[dict]:
        records = []
        aad = f"reconclave-spool/v1|{self.node_id}".encode()
        for line in path.read_text(encoding="utf-8").splitlines():
            frame = json.loads(line)
            if frame.get("v") != 1 or frame.get("node") != self.node_id:
                raise ValueError("encrypted spool frame identity mismatch")
            plaintext = AESGCM(self.key).decrypt(base64.b64decode(frame["nonce"]),
                                                  base64.b64decode(frame["ciphertext"]), aad)
            records.append(json.loads(plaintext))
        return records
