import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import auto
import fivem_connection_probe as probe


def candidates():
    return {
        "current": {"address": "203.0.113.10:30120", "score": 100},
        "other": {"address": "203.0.113.20:30120", "score": 80},
    }


class AutoTargetTests(unittest.TestCase):
    def test_large_log_keeps_launch_uri_and_recent_connection_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "CitizenFX_log_current.log"
            log_path.write_bytes(
                b'hello from FiveM.exe "fivem://connect/203.0.113.10:30120"\n'
                + b"x" * (2 * probe.DEFAULT_LOG_TAIL_BYTES)
                + b"\nFailed to connect to 203.0.113.20 port 30120\n"
            )
            excerpt = probe.read_log_excerpt(log_path, probe.DEFAULT_LOG_TAIL_BYTES)
            self.assertLessEqual(len(excerpt), probe.DEFAULT_LOG_TAIL_BYTES + 1)
            found = {}
            probe.scan_recent_logs([], found, logs_dir=temp_dir)

        self.assertIn("203.0.113.10:30120", found)
        self.assertIn("203.0.113.20:30120", found)

    @mock.patch.object(probe.requests, "Session")
    def test_success_stops_before_remaining_candidates_and_closes_connections(self, session_factory):
        session = session_factory.return_value
        response = session.post.return_value
        response.status_code = 200
        response.json.return_value = {"resources": [{"name": "example"}]}
        messages = []

        result = probe.verify_candidates(
            candidates(), ".", token="test-token", on_progress=messages.append,
        )

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["verified"]["address"], "203.0.113.10:30120")
        self.assertEqual(result["verified"]["resource_count"], 1)
        self.assertEqual(result["verified"]["resource_names"], ["example"])
        session.post.assert_called_once()
        response.close.assert_called_once()
        session.close.assert_called_once()
        self.assertTrue(messages)
        self.assertNotIn("test-token", " ".join(messages))

    @mock.patch.object(probe.requests, "Session")
    def test_http_fallback_stops_after_success(self, session_factory):
        session = session_factory.return_value
        response = mock.Mock(status_code=200)
        response.json.return_value = {"resources": []}
        session.post.side_effect = [probe.requests.ConnectionError(), response]

        result = probe.verify_candidates(candidates(), ".", token="test-token")

        self.assertEqual(result["verified"]["transport"], "http")
        self.assertEqual(session.post.call_count, 2)
        self.assertEqual(len(result["tested"]), 1)

    @mock.patch.object(probe.requests, "Session")
    def test_invalid_configuration_is_not_accepted(self, session_factory):
        session = session_factory.return_value
        response = session.post.return_value
        response.status_code = 200
        response.json.return_value = {"error": "invalid token"}

        result = probe.verify_candidates(candidates(), ".", token="test-token")

        self.assertIsNone(result["verified"])
        self.assertEqual(len(result["tested"]), 2)
        self.assertEqual(session.post.call_count, 4)

    @mock.patch.object(probe, "verify_candidates")
    @mock.patch.object(probe, "scan_process_memory")
    @mock.patch.object(probe, "scan_network_connections")
    @mock.patch.object(probe, "scan_recent_logs")
    @mock.patch.object(probe, "collect_fivem_processes")
    def test_verified_log_hint_skips_memory(self, collect, logs, network, memory, verify):
        collect.return_value = [{"pid": 10, "name": "FiveM", "game": True}]

        def scan_logs(_processes, found, **_kwargs):
            found["current"] = dict(candidates()["current"], source="recent-citizenfx-log")
            return []

        logs.side_effect = scan_logs
        verify.return_value = {"status": "verified", "verified": dict(candidates()["current"], resource_count=1)}
        result = probe.run_probe(probe.parse_args(["--verify", "--allow-stale-logs"]), token="test-token")

        self.assertEqual(result["status"], "verified")
        memory.assert_not_called()
        verify.assert_called_once()
        self.assertTrue(logs.call_args[1]["allow_stale"])
        self.assertEqual(verify.call_args[1]["token"], "test-token")

    @mock.patch.object(probe, "verify_candidates")
    @mock.patch.object(probe, "scan_process_memory")
    @mock.patch.object(probe, "scan_network_connections")
    @mock.patch.object(probe, "scan_recent_logs")
    @mock.patch.object(probe, "collect_fivem_processes")
    def test_rejected_log_hint_still_uses_memory_fallback(self, collect, logs, network, memory, verify):
        collect.return_value = [{"pid": 10, "name": "FiveM", "game": True}]

        def scan_logs(_processes, found, **_kwargs):
            found["old"] = dict(candidates()["current"], source="recent-citizenfx-log")
            return []

        logs.side_effect = scan_logs

        def scan_memory(_processes, found, **_kwargs):
            found["current"] = dict(candidates()["other"], source="process-memory")
            return {"scanned": True}

        memory.side_effect = scan_memory
        verify.side_effect = [
            {"status": "tested", "verified": None, "tested": [candidates()["current"]]},
            {"status": "verified", "verified": dict(candidates()["other"], resource_count=1)},
        ]

        result = probe.run_probe(probe.parse_args(["--verify", "--allow-stale-logs"]), token="test-token")

        self.assertEqual(result["selected"]["address"], "203.0.113.20:30120")
        memory.assert_called_once()
        self.assertEqual(verify.call_count, 2)

    @mock.patch.object(probe.requests, "Session")
    @mock.patch.object(probe, "scan_process_memory")
    @mock.patch.object(probe, "scan_network_connections")
    @mock.patch.object(probe, "scan_recent_logs")
    @mock.patch.object(probe, "collect_fivem_processes")
    def test_timed_out_log_address_can_succeed_after_memory_scan(self, collect, logs, network, memory, session_factory):
        collect.return_value = [{"pid": 10, "name": "FiveM", "game": True}]

        def scan_logs(_processes, found, **_kwargs):
            probe.add_candidate(found, "203.0.113.10:30120", "recent-citizenfx-log", 86)
            return []

        def scan_memory(_processes, found, **_kwargs):
            probe.add_candidate(found, "203.0.113.10:30120", "process-memory", 82)
            return {"scanned": True}

        logs.side_effect = scan_logs
        memory.side_effect = scan_memory
        response = mock.Mock(status_code=200)
        response.json.return_value = {"resources": [{"name": "example"}]}
        session_factory.return_value.post.side_effect = [
            probe.requests.Timeout(), probe.requests.Timeout(), response,
        ]

        result = probe.run_probe(probe.parse_args(["--verify"]), token="test-token")

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["selected"]["address"], "203.0.113.10:30120")

    @mock.patch.object(auto, "FiveMDumper")
    @mock.patch.object(auto, "resolve_target_from_fivem")
    @mock.patch.object(auto, "choose_token", return_value="test-token")
    def test_listing_reuses_verified_resources_without_a_second_request(self, choose, resolve, dumper):
        resolve.return_value = {
            "address": "203.0.113.10:30120",
            "transport": "http",
            "resource_names": ["example"],
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output), mock.patch.object(auto, "resolve_server_endpoint") as endpoint:
            code = auto.run_resource_listing(auto.parse_args(["--auto-target", "--list-resources", "--non-interactive"]))

        self.assertEqual(code, 0)
        self.assertIn('"name": "example"', output.getvalue())
        self.assertIn('"base_url": "http://203.0.113.10:30120"', output.getvalue())
        payload = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(payload["target"], "http://203.0.113.10:30120")
        with contextlib.redirect_stdout(io.StringIO()):
            next_endpoint = auto.resolve_server_endpoint(payload["target"], token="test-token")
        self.assertEqual(next_endpoint["base_urls"], ["http://203.0.113.10:30120"])
        endpoint.assert_not_called()
        dumper.assert_not_called()
        resolve.assert_called_once_with("test-token")

    @mock.patch.object(auto, "load_target_probe_module")
    def test_toolbox_receives_progress_and_failed_verification_error(self, load_probe):
        fake_probe = load_probe.return_value
        fake_probe.parse_args.return_value = probe.parse_args([])

        def detect(_args, on_progress, token):
            on_progress("scan heartbeat")
            return {
                "candidates": list(candidates().values()),
                "verification": {"status": "tested", "verified": None},
            }

        fake_probe.run_probe.side_effect = detect
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(auto.SessionPauseError, "没有候选通过当前 FiveM Token 验证"):
                auto.resolve_target_from_fivem("test-token")

        self.assertIn("[地址] scan heartbeat", output.getvalue())
        self.assertIn("CK_PROGRESS ", output.getvalue())
        self.assertNotIn("test-token", output.getvalue())


if __name__ == "__main__":
    unittest.main()
