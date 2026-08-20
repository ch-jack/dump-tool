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


if __name__ == "__main__":
    unittest.main()
