import json
import tempfile
import unittest
from pathlib import Path

import auto


class FileListTests(unittest.TestCase):
    def test_builds_file_list_payload_without_resource_secrets(self):
        resources = [
            {
                "name": "example_resource",
                "uri": "secret-uri",
                "fileServer": "https://files.example.invalid",
                "files": {
                    "fxmanifest.lua": {"hash": "manifest-hash"},
                    "scripts/main.lua": "script-hash",
                },
                "streamFiles": {
                    "model.ytd": {"hash": "stream-hash"},
                },
            }
        ]

        payload = auto.build_file_list_payload(
            resources,
            "127.0.0.1:30120",
            "127.0.0.1:30120",
            "http://127.0.0.1:30120",
        )

        self.assertEqual(payload["command"], "list-files")
        self.assertEqual(payload["summary"]["total_files"], 3)
        self.assertEqual(payload["resources"][0]["files"][1]["path"], "scripts/main.lua")
        self.assertEqual(payload["resources"][0]["stream_files"][0]["hash"], "stream-hash")
        self.assertNotIn("uri", json.dumps(payload))
        self.assertNotIn("fileServer", json.dumps(payload))

    def test_resolves_json_and_text_output_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path, text_path = auto.resolve_file_list_paths(Path(temp_dir) / "server_file_list.json")
            self.assertEqual(json_path.name, "server_file_list.json")
            self.assertEqual(text_path.name, "server_file_list.txt")

    def test_builds_human_readable_text(self):
        payload = {
            "target": "127.0.0.1:30120",
            "server_address": "127.0.0.1:30120",
            "generated_at": "2026-11-18T00:00:00",
            "summary": {"resources": 1, "files": 1, "stream_files": 1, "total_files": 2},
            "resources": [
                {
                    "index": 0,
                    "name": "example_resource",
                    "files": [{"path": "fxmanifest.lua"}],
                    "stream_files": [{"path": "model.ytd"}],
                }
            ],
        }

        text = auto.build_file_list_text(payload)

        self.assertIn("example_resource/fxmanifest.lua", text)
        self.assertIn("example_resource/stream/model.ytd", text)

    def test_output_write_failure_returns_error(self):
        class DummyDumper:
            base_url = "http://127.0.0.1:30120"

            def get_configuration(self, save_grants=True):
                return [{"name": "example_resource", "files": {}, "streamFiles": {}}]

        original = (auto.choose_token, auto.resolve_server_endpoint, auto.FiveMDumper, auto.write_json_atomic)
        auto.choose_token = lambda args: "token"
        auto.resolve_server_endpoint = lambda target, token: {
            "address": "127.0.0.1:30120",
            "base_urls": ["http://127.0.0.1:30120"],
        }
        auto.FiveMDumper = lambda *args, **kwargs: DummyDumper()

        def fail_write(path, payload):
            raise OSError("write failed")

        auto.write_json_atomic = fail_write
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                args = auto.parse_args(
                    [
                        "127.0.0.1:30120",
                        "--token-choice",
                        "1",
                        "--list-files",
                        "--file-list-output",
                        str(Path(temp_dir) / "server_file_list.json"),
                        "--non-interactive",
                    ]
                )
                self.assertEqual(auto.run_file_listing(args), 2)
        finally:
            auto.choose_token, auto.resolve_server_endpoint, auto.FiveMDumper, auto.write_json_atomic = original


if __name__ == "__main__":
    unittest.main()
