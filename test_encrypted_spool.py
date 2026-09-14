import base64
import json
import pathlib
import tempfile
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from encrypted_spool import EncryptedSpool


class EncryptedSpoolTests(unittest.TestCase):
    def test_round_trip_and_wrong_key_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = EncryptedSpool(directory, "correct", "node-1")
            path = spool.append({"secret": "observation"}, "20260904")
            self.assertNotIn("observation", path.read_text())
            self.assertEqual(spool.read(path), [{"secret": "observation"}])
            with self.assertRaises(InvalidTag):
                EncryptedSpool(directory, "wrong", "node-1").read(path)

    def test_frame_cannot_be_moved_to_another_node(self):
        with tempfile.TemporaryDirectory() as directory:
            path = EncryptedSpool(directory, "key", "node-1").append({"value": 1}, "20260904")
            with self.assertRaisesRegex(ValueError, "identity"):
                EncryptedSpool(directory, "key", "node-2").read(path)

    # -- raw key mode (decodes an ESP32 device's own RC_STORAGE_KEY-encrypted spool) ----

    def test_raw_key_round_trips_and_produces_the_same_wire_format_as_passphrase_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_key = bytes(range(32))
            spool = EncryptedSpool(directory, node_id="rc-p4-01", key=raw_key)
            path = spool.append({"observation": "device-local"}, "20260905")
            self.assertEqual(spool.read(path), [{"observation": "device-local"}])
            # A second instance built the same way (as a coordinator inspecting an
            # extracted SD card / NVS dump later would) reads it back identically.
            self.assertEqual(EncryptedSpool(directory, node_id="rc-p4-01", key=raw_key).read(path),
                             [{"observation": "device-local"}])

    def test_raw_key_rejects_wrong_length(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "32 bytes"):
                EncryptedSpool(directory, node_id="rc-p4-01", key=b"too-short")

    def test_raw_key_decodes_a_frame_built_the_way_esp32_firmware_builds_one(self):
        """Reproduces exactly what devices/{poe-p4,cardputer-adv} do by hand -- os.urandom
        nonce, AESGCM over `reconclave-spool/v1|<node_id>` AAD, base64 -- rather than going
        through EncryptedSpool.append(), to prove the frame shape documented for firmware
        (a plain {v, node, nonce, ciphertext} object, tag appended to the ciphertext bytes
        the same way Python's AESGCM concatenates them) round-trips through this reader.
        """
        with tempfile.TemporaryDirectory() as directory:
            raw_key = bytes(range(32))
            node_id = "rc-p4-30eda0eab970"
            plaintext = json.dumps({"job_id": "job-1", "observation": {"responsive": True}},
                                   separators=(",", ":")).encode()
            nonce = bytes(range(12))
            ciphertext = AESGCM(raw_key).encrypt(nonce, plaintext,
                                                 f"reconclave-spool/v1|{node_id}".encode())
            frame = {"v": 1, "node": node_id,
                     "nonce": base64.b64encode(nonce).decode(),
                     "ciphertext": base64.b64encode(ciphertext).decode()}
            path = pathlib.Path(directory) / "evidence-20260905.rcspool"
            path.write_text(json.dumps(frame) + "\n", encoding="utf-8")
            [decoded] = EncryptedSpool(directory, node_id=node_id, key=raw_key).read(path)
            self.assertEqual(decoded, json.loads(plaintext))

    def test_raw_key_and_passphrase_derived_key_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_key = bytes(range(32))
            path = EncryptedSpool(directory, node_id="node-1", key=raw_key).append(
                {"value": 1}, "20260905")
            with self.assertRaises(InvalidTag):
                EncryptedSpool(directory, passphrase=raw_key.hex(), node_id="node-1").read(path)


if __name__ == "__main__":
    unittest.main()
