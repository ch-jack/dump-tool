import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests
from Crypto.Cipher import ChaCha20

import auto


class FakeResponse:
    def __init__(self, status_code, content=b"", reason="", headers=None):
        self.status_code = status_code
        self.content = content
        self.reason = reason
        self.headers = headers or {}
        self.closed = False

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def get(self, _url, timeout=None):
        self.calls += 1
        if timeout != (15, 60):
            raise AssertionError(f"unexpected timeout: {timeout}")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class DownloadRetryTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.iv = bytes(range(8))
        self.plaintext = b"RPF retry test payload"
        self.encrypted = ChaCha20.new(key=self.key, nonce=self.iv).encrypt(self.plaintext)

    def new_dumper(self, outcomes):
        dumper = auto.FiveMDumper("https://127.0.0.1:30120", "test-token")
        dumper.session = FakeSession(outcomes)
        return dumper

    @mock.patch("auto.time.sleep")
    def test_403_and_404_are_retried_then_recovered(self, sleep_mock):
        responses = [
            FakeResponse(403, reason="Forbidden"),
            FakeResponse(404, reason="Not Found", headers={"Retry-After": "0"}),
            FakeResponse(200, content=self.encrypted, reason="OK"),
        ]
        dumper = self.new_dumper(responses)
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "retry.rpf"
            result = dumper.download_and_decrypt(
                "https://files.example/retry.rpf",
                self.key,
                self.iv,
                str(output),
                "retry.rpf",
                "example_resource",
            )
            self.assertEqual(output.read_bytes(), self.plaintext)

        self.assertEqual(result["attempts"], 3)
        self.assertEqual(result["retries"], 2)
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["failure_stage"], "")
        self.assertEqual(sleep_mock.call_count, 2)
        self.assertTrue(all(response.closed for response in responses))

    @mock.patch("auto.time.sleep")
    def test_permanent_404_records_final_failure(self, sleep_mock):
        responses = [FakeResponse(404, reason="Not Found") for _ in range(auto.DOWNLOAD_MAX_ATTEMPTS)]
        dumper = self.new_dumper(responses)
        result = dumper.download_and_decrypt(
            "https://files.example/missing.ydr",
            self.key,
            self.iv,
            "unused.ydr",
            "missing.ydr",
            "example_resource",
        )

        self.assertIsNone(result["path"])
        self.assertEqual(result["failure_stage"], "download")
        self.assertEqual(result["status_code"], 404)
        self.assertEqual(result["attempts"], auto.DOWNLOAD_MAX_ATTEMPTS)
        self.assertEqual(result["retries"], auto.DOWNLOAD_MAX_ATTEMPTS - 1)
        self.assertEqual(sleep_mock.call_count, auto.DOWNLOAD_MAX_ATTEMPTS - 1)
        self.assertTrue(all(response.closed for response in responses))

    @mock.patch("auto.time.sleep")
    def test_timeout_is_retried(self, sleep_mock):
        response = FakeResponse(200, content=self.encrypted, reason="OK")
        dumper = self.new_dumper([requests.exceptions.Timeout("timed out"), response])
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "timeout.rpf"
            result = dumper.download_and_decrypt(
                "https://files.example/timeout.rpf",
                self.key,
                self.iv,
                str(output),
                "timeout.rpf",
                "example_resource",
            )
            self.assertEqual(output.read_bytes(), self.plaintext)

        self.assertEqual(result["attempts"], 2)
        self.assertEqual(result["retries"], 1)
        sleep_mock.assert_called_once()
        self.assertTrue(response.closed)

    def test_resource_summary_keeps_all_final_download_failures(self):
        dumper = auto.FiveMDumper("https://127.0.0.1:30120", "test-token")
        raw_uri = bytes(range(61))
        resource = {
            "name": "example_resource",
            "uri": "test#" + base64.b64encode(raw_uri).decode("ascii"),
            "files": {
                "good.lua": {"hash": "good-hash"},
                "missing.lua": {"hash": "missing-hash"},
                "no-hash.lua": {},
            },
            "streamFiles": {},
        }

        def fake_download(_url, _key, _iv, out_path, file_name, _resource_name):
            if file_name == "good.lua":
                return {
                    "path": out_path,
                    "file": file_name,
                    "bytes": 10,
                    "attempts": 2,
                    "retries": 1,
                    "status_code": 200,
                    "failure_stage": "",
                    "error": "",
                }
            return {
                "path": None,
                "file": file_name,
                "bytes": 0,
                "attempts": 4,
                "retries": 3,
                "status_code": 404,
                "failure_stage": "download",
                "error": "HTTP 404 Not Found",
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            old_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                with mock.patch.object(dumper, "download_and_decrypt", side_effect=fake_download):
                    item = dumper.fetch_resource(resource, 1, 1)
            finally:
                os.chdir(old_cwd)

        self.assertEqual(item["status"], "partial")
        self.assertEqual(item["downloaded_files"], 1)
        self.assertEqual(item["failed_files"], 2)
        self.assertEqual(item["download_retried_files"], 2)
        self.assertEqual(item["download_retry_attempts"], 4)
        self.assertEqual(item["download_retry_recovered"], 1)
        self.assertEqual([failure["file"] for failure in item["failed_downloads"]], ["no-hash.lua", "missing.lua"])
        self.assertEqual(dumper.summary["failed_downloads"], 2)
        self.assertEqual(dumper.summary["download_retry_recovered"], 1)

        markdown = auto.build_markdown_report(
            {
                "summary": {
                    "downloaded_files": 1,
                    "download_retried_files": 2,
                    "download_retry_attempts": 4,
                    "download_retry_recovered": 1,
                    "failed_downloads": 2,
                },
                "dump_resources": [item],
            }
        )
        self.assertIn("## 最终未下载成功文件", markdown)
        self.assertIn("example_resource/no-hash.lua", markdown)
        self.assertIn("example_resource/missing.lua: HTTP 404，尝试 4 次", markdown)

    def test_supplement_download_only_schedules_failures_and_decrypt_prerequisite(self):
        dumper = auto.FiveMDumper(
            "https://127.0.0.1:30120",
            "test-token",
            retry_files_by_resource={"example_resource": ["failed.lua", "failed.ydr"]},
            include_decrypt_prerequisites=True,
            retry_resource_is_fxap={"example_resource": True},
        )
        raw_uri = bytes(range(61))
        resource = {
            "name": "example_resource",
            "uri": "test#" + base64.b64encode(raw_uri).decode("ascii"),
            "files": {
                "resource.rpf": {"hash": "rpf-hash"},
                "failed.lua": {"hash": "failed-lua-hash"},
                "already-ok.lua": {"hash": "ok-lua-hash"},
            },
            "streamFiles": {
                "failed.ydr": {"hash": "failed-stream-hash"},
                "already-ok.ydr": {"hash": "ok-stream-hash"},
            },
        }
        scheduled = []

        def fake_download(_url, _key, _iv, out_path, file_name, _resource_name):
            scheduled.append(file_name)
            path = Path(out_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"downloaded")
            return {
                "path": str(path),
                "file": file_name,
                "bytes": 10,
                "attempts": 1,
                "retries": 0,
                "status_code": 200,
                "failure_stage": "",
                "error": "",
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            old_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                with mock.patch.object(dumper, "download_and_decrypt", side_effect=fake_download), mock.patch.object(
                    dumper,
                    "unpack_rpf",
                    return_value=True,
                ):
                    item = dumper.fetch_resource(resource, 1, 1)
            finally:
                os.chdir(old_cwd)

        self.assertEqual(set(scheduled), {"resource.rpf", "failed.lua", "failed.ydr"})
        self.assertNotIn("already-ok.lua", scheduled)
        self.assertNotIn("already-ok.ydr", scheduled)
        self.assertEqual(item["retry_requested_files"], ["failed.lua", "failed.ydr"])
        self.assertEqual(item["retry_prerequisite_files"], ["resource.rpf"])
        self.assertEqual(set(item["retry_recovered_files"]), {"failed.lua", "failed.ydr"})
        self.assertEqual(dumper.summary["retry_requested_files"], 2)
        self.assertEqual(dumper.summary["retry_recovered_files"], 2)
        self.assertEqual(dumper.summary["retry_prerequisite_files"], 1)

    def test_unavailable_old_resource_does_not_abort_other_supplements(self):
        dumper = auto.FiveMDumper(
            "https://127.0.0.1:30120",
            "test-token",
            retry_files_by_resource={
                "available_resource": ["missing.lua"],
                "removed_resource": ["old.ydr", "old.ytd"],
            },
        )
        fetched = []

        def fake_fetch(resource, _index, _total):
            fetched.append(resource["name"])
            dumper.summary["retry_requested_files"] += 1
            dumper.summary["retry_recovered_files"] += 1
            item = {
                "name": resource["name"],
                "status": "success",
                "retry_mode": True,
                "retry_requested_files": ["missing.lua"],
                "retry_recovered_files": ["missing.lua"],
                "retry_pending_files": [],
                "retry_prerequisite_files": [],
                "failed_downloads": [],
                "warnings": [],
                "errors": [],
            }
            dumper.resource_reports.append(item)
            return item

        with mock.patch.object(
            dumper,
            "get_configuration",
            return_value=[{"name": "available_resource"}],
        ), mock.patch.object(dumper, "fetch_resource", side_effect=fake_fetch):
            result = dumper.run(["available_resource", "removed_resource"])

        self.assertEqual(fetched, ["available_resource"])
        removed = next(item for item in result if item["name"] == "removed_resource")
        self.assertEqual(removed["status"], "unavailable")
        self.assertEqual(removed["retry_pending_files"], ["old.ydr", "old.ytd"])
        self.assertEqual(dumper.summary["retry_requested_files"], 3)
        self.assertEqual(dumper.summary["retry_remaining_files"], 2)
        self.assertEqual(dumper.summary["warnings"], 1)


if __name__ == "__main__":
    unittest.main()
