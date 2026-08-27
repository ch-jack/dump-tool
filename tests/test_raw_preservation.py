import tempfile
import unittest
import json
import os
from pathlib import Path
from unittest import mock

import auto


class RawResourcePreservationTests(unittest.TestCase):
    def test_preserves_fxap_and_complete_directory_without_java(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source" / "protected_resource"
            output = root / "output"
            (source / "stream" / "nested").mkdir(parents=True)
            (source / ".fxap").write_bytes(b"FXAP\x00raw-license-data")
            (source / "fxmanifest.lua").write_text("fx_version 'cerulean'\n", encoding="utf-8")
            (source / "client.lua").write_bytes(b"encrypted-client-content")
            (source / "stream" / "nested" / "model.ydr").write_bytes(b"encrypted-model-content")

            processor = auto.FiveMDecryptor(
                output_dir=str(output),
                java_executable="",
                require_java=False,
            )
            result = processor.preserve_raw_resource(str(source), "protected_resource")
            destination = output / "protected_resource"

            source_files = {
                path.relative_to(source).as_posix(): path.read_bytes()
                for path in source.rglob("*")
                if path.is_file()
            }
            output_files = {
                path.relative_to(destination).as_posix(): path.read_bytes()
                for path in destination.rglob("*")
                if path.is_file()
            }

            self.assertEqual(result["status"], "raw_preserved")
            self.assertTrue(result["is_fxap"])
            self.assertTrue(result["raw_preserved"])
            self.assertEqual(result["files_total"], 4)
            self.assertEqual(result["copied_files"], 4)
            self.assertEqual(source_files, output_files)
            self.assertEqual(processor.summary["resources_raw_preserved"], 1)

            report = auto.build_markdown_report(
                {
                    "scope": {
                        "serverDump": True,
                        "fxapDecrypt": False,
                        "rawResourcePreservation": True,
                    },
                    "java": {"required": False, "ok": False},
                    "summary": {"resources_raw_preserved": 1},
                    "raw_resources": [result],
                }
            )
            self.assertIn("原始 FXAP 资源完整保留: 包含", report)
            self.assertIn("本次是否需要: 否", report)
            self.assertIn("## 原始资源完整保留", report)
            self.assertIn("[raw_preserved] protected_resource", report)

    def test_cli_raw_mode_defaults_off(self):
        default_args = auto.parse_args([])
        raw_args = auto.parse_args(["--no-fxap-decrypt"])
        self.assertFalse(default_args.no_fxap_decrypt)
        self.assertTrue(raw_args.no_fxap_decrypt)

    def test_retry_report_loads_failed_and_pending_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "previous.json"
            report_path.write_text(
                json.dumps(
                    {
                        "command": "server-dump",
                        "target": "cfx.re/join/example",
                        "output": str(Path(temp_dir) / "output"),
                        "scope": {"fxapDecrypt": True, "rawResourcePreservation": False},
                        "dump_resources": [
                            {
                                "name": "protected_resource",
                                "failed_downloads": [{"file": "stream/missing.ydr"}],
                                "retry_pending_files": ["client.lua", "stream/missing.ydr"],
                            }
                        ],
                        "decrypt_resources": [{"name": "protected_resource", "is_fxap": True}],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            plan = auto.load_failed_download_retry_report(report_path)

            self.assertEqual(plan["target"], "cfx.re/join/example")
            self.assertFalse(plan["raw_mode"])
            self.assertEqual(
                plan["files_by_resource"]["protected_resource"],
                ["stream/missing.ydr", "client.lua"],
            )
            self.assertTrue(plan["resource_is_fxap"]["protected_resource"])
            self.assertEqual(plan["requested_files"], 2)

    def test_incomplete_download_is_not_reported_as_complete_raw_resource(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source" / "partial_resource"
            source.mkdir(parents=True)
            (source / ".fxap").write_bytes(b"FXAP partial")
            processor = auto.FiveMDecryptor(output_dir=str(root / "output"), require_java=False)
            result = processor.preserve_raw_resource(
                str(source),
                "partial_resource",
                source_complete=False,
                source_failed_files=2,
            )

            self.assertEqual(result["status"], "partial")
            self.assertFalse(result["source_complete"])
            self.assertEqual(result["source_failed_files"], 2)
            self.assertEqual(processor.summary["resources_raw_preserved"], 0)
            self.assertIn("内容不完整", result["warnings"][0])

    def test_full_raw_mode_skips_java_and_reports_preserved_resource(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "downloaded" / "protected_resource"
            output = root / "output"
            report_path = root / "report.json"
            (source / "stream").mkdir(parents=True)
            (source / ".fxap").write_bytes(b"FXAP raw")
            (source / "fxmanifest.lua").write_text("fx_version 'cerulean'\n", encoding="utf-8")
            (source / "stream" / "model.ydr").write_bytes(b"encrypted model")

            args = auto.parse_args(
                [
                    "127.0.0.1:30120",
                    "--token-choice",
                    "1",
                    "--resources",
                    "all",
                    "--output",
                    str(output),
                    "--report",
                    str(report_path),
                    "--non-interactive",
                    "--no-fxap-decrypt",
                ]
            )

            def fake_dump_run(dumper, _resources_choice, on_resource_ready=None):
                dumper.summary["resources_total"] = 1
                dumper.summary["resources_selected"] = 1
                dumper.summary["downloaded_files"] = 3
                dumper.resource_reports.append(
                    {
                        "name": "protected_resource",
                        "status": "success",
                        "files_total": 3,
                        "downloaded_files": 3,
                        "failed_files": 0,
                        "rpf_unpacked": 1,
                        "warnings": [],
                        "errors": [],
                    }
                )
                on_resource_ready(str(source), "protected_resource", dumper.resource_reports[0])
                return dumper.resource_reports

            old_cwd = os.getcwd()
            try:
                with mock.patch("auto.choose_token", return_value="test-token"), mock.patch(
                    "auto.resolve_server_endpoint",
                    return_value={"address": "127.0.0.1:30120", "base_urls": ["http://127.0.0.1:30120"]},
                ), mock.patch("auto.FiveMDumper.run", autospec=True, side_effect=fake_dump_run), mock.patch(
                    "auto.resolve_java_executable",
                    side_effect=AssertionError("raw mode must not inspect Java"),
                ):
                    exit_code = auto.run_tool(args)
            finally:
                os.chdir(old_cwd)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertEqual(report["status"], "success")
            self.assertFalse(report["scope"]["fxapDecrypt"])
            self.assertTrue(report["scope"]["rawResourcePreservation"])
            self.assertFalse(report["java"]["required"])
            self.assertEqual(report["summary"]["resources_raw_preserved"], 1)
            self.assertEqual(report["raw_resources"][0]["status"], "raw_preserved")
            self.assertEqual((output / "protected_resource" / ".fxap").read_bytes(), b"FXAP raw")

    def test_supplement_keeps_recovered_file_pending_when_fxap_context_is_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "output"
            previous_report = root / "previous.json"
            new_report = root / "supplement.json"
            source = root / "retry-source" / "protected_resource"
            fake_java = root / "java.exe"
            source.mkdir(parents=True)
            (source / "missing.ydr").write_bytes(b"recovered encrypted model")
            fake_java.write_bytes(b"fake")
            previous_report.write_text(
                json.dumps(
                    {
                        "command": "server-dump",
                        "target": "127.0.0.1:30120",
                        "output": str(output),
                        "scope": {"fxapDecrypt": True, "rawResourcePreservation": False},
                        "dump_resources": [
                            {
                                "name": "protected_resource",
                                "failed_downloads": [{"file": "missing.ydr"}],
                            }
                        ],
                        "decrypt_resources": [{"name": "protected_resource", "is_fxap": True}],
                    }
                ),
                encoding="utf-8",
            )
            args = auto.parse_args(
                [
                    "--retry-failed-report",
                    str(previous_report),
                    "--report",
                    str(new_report),
                    "--non-interactive",
                ]
            )

            captured = {}

            def fake_retry_run(dumper, resources_choice, on_resource_ready=None):
                captured["resources_choice"] = resources_choice
                captured["retry_filter"] = dumper.retry_files_by_resource
                dumper.summary["resources_total"] = 1
                dumper.summary["resources_selected"] = 1
                dumper.summary["downloaded_files"] = 1
                dumper.summary["retry_requested_files"] = 1
                dumper.summary["retry_recovered_files"] = 1
                item = {
                    "name": "protected_resource",
                    "status": "success",
                    "files_total": 2,
                    "downloaded_files": 1,
                    "download_retried_files": 0,
                    "download_retry_attempts": 0,
                    "download_retry_recovered": 0,
                    "failed_downloads": [],
                    "retry_mode": True,
                    "retry_requested_files": ["missing.ydr"],
                    "retry_recovered_files": ["missing.ydr"],
                    "retry_pending_files": [],
                    "retry_prerequisite_files": ["resource.rpf"],
                    "retry_prerequisite_failed": True,
                    "failed_files": 0,
                    "rpf_unpacked": 0,
                    "warnings": [],
                    "errors": [],
                }
                dumper.resource_reports.append(item)
                on_resource_ready(str(source), "protected_resource", item)
                return dumper.resource_reports

            old_cwd = os.getcwd()
            try:
                with mock.patch("auto.choose_token", return_value="test-token"), mock.patch(
                    "auto.resolve_server_endpoint",
                    return_value={"address": "127.0.0.1:30120", "base_urls": ["http://127.0.0.1:30120"]},
                ), mock.patch("auto.resolve_java_executable", return_value={
                    "ok": True,
                    "path": str(fake_java),
                    "version": 'java version "17"',
                    "major": 17,
                }), mock.patch("auto.FiveMDumper.run", autospec=True, side_effect=fake_retry_run):
                    exit_code = auto.run_tool(args)
            finally:
                os.chdir(old_cwd)

            report = json.loads(new_report.read_text(encoding="utf-8"))
            next_plan = auto.load_failed_download_retry_report(new_report)
            self.assertEqual(exit_code, 10)
            self.assertEqual(captured["resources_choice"], ["protected_resource"])
            self.assertIn("missing.ydr", captured["retry_filter"]["protected_resource"])
            self.assertEqual(report["dump_resources"][0]["retry_pending_files"], ["missing.ydr"])
            self.assertEqual(report["retry_failed"]["remaining_files"], 1)
            self.assertEqual(next_plan["files_by_resource"]["protected_resource"], ["missing.ydr"])


if __name__ == "__main__":
    unittest.main()
