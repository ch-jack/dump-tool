import base64
import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests
from Crypto.Cipher import ChaCha20

import auto


class FakeResponse:
    def __init__(self, content):
        self.status_code = 200
        self.content = content
        self.reason = "OK"
        self.headers = {}
        self.closed = False

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)

    def get(self, _url, timeout=None):
        if timeout != (15, 60):
            raise AssertionError(timeout)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class ResumeTests(unittest.TestCase):
    def test_wait_mode_writes_status_and_pauses_without_token(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            status_path = Path(temp_dir) / "status.json"
            auto.STATUS_FILE = str(status_path)
            auto.update_status_file(
                status="waiting-game",
                percent=4,
                stage="token",
                message="等待 FiveM",
                completed_resources=2,
            )
            payload = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "waiting-game")
            self.assertEqual(payload["completed_resources"], 2)

        args = argparse.Namespace(token_choice="1", token="", non_interactive=True, wait_for_game=True)
        with mock.patch.object(auto, "get_token", return_value=None):
            with self.assertRaises(auto.SessionPauseError):
                auto.choose_token(args)
        auto.STATUS_FILE = None

    def test_session_is_written_atomically_and_loaded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            auto.write_json_atomic(path, {"command": "server-dump", "status": "paused"})
            payload = auto.load_dump_session(path)
            self.assertEqual(payload["status"], "paused")
            self.assertEqual(payload["session_file"], str(path.resolve()))
            self.assertFalse((Path(str(path) + ".tmp")).exists())

    def test_completed_resource_is_skipped(self):
        dumper = auto.FiveMDumper("https://127.0.0.1:30120", "test-token")
        dumper.completed_resources = {"already_done"}
        fetched = []
        resource = {
            "name": "already_done",
            "uri": "test#" + base64.b64encode(bytes(range(61))).decode("ascii"),
            "files": {},
            "streamFiles": {},
        }
        with mock.patch.object(dumper, "get_configuration", return_value=[resource]), mock.patch.object(
            dumper, "fetch_resource", side_effect=lambda *_args: fetched.append(True)
        ):
            dumper.run(["already_done"])
        self.assertEqual(fetched, [])

    @mock.patch("auto.time.sleep")
    def test_connection_loss_is_marked_for_resume(self, _sleep):
        key = bytes(range(32))
        iv = bytes(range(8))
        dumper = auto.FiveMDumper("https://127.0.0.1:30120", "test-token")
        dumper.session = FakeSession([requests.exceptions.ConnectionError("closed") for _ in range(4)])
        result = dumper.download_and_decrypt(
            "https://files.example/file",
            key,
            iv,
            "unused.bin",
            "file.bin",
            "example_resource",
        )
        self.assertTrue(result["connection_lost"])
        self.assertIsNone(result["path"])

    def test_completed_download_has_no_part_file(self):
        key = bytes(range(32))
        iv = bytes(range(8))
        plain = b"resume test"
        encrypted = ChaCha20.new(key=key, nonce=iv).encrypt(plain)
        dumper = auto.FiveMDumper("https://127.0.0.1:30120", "test-token")
        dumper.session = FakeSession([FakeResponse(encrypted)])
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "file.bin"
            result = dumper.download_and_decrypt("https://files.example/file", key, iv, str(output), "file.bin")
            self.assertEqual(result["path"], str(output))
            self.assertEqual(output.read_bytes(), plain)
            self.assertFalse(Path(str(output) + ".part").exists())


if __name__ == "__main__":
    unittest.main()
