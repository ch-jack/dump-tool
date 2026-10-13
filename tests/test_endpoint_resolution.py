import unittest
from unittest import mock

import auto


class FakeResponse:
    def __init__(self, headers=None, payload=None, error=None):
        self.headers = headers or {}
        self.payload = payload
        self.error = error
        self.closed = False

    def raise_for_status(self):
        if self.error:
            raise self.error

    def json(self):
        return self.payload

    def close(self):
        self.closed = True


class EndpointResolutionTests(unittest.TestCase):
    @mock.patch("auto.requests.post")
    @mock.patch("auto.requests.get")
    def test_cfx_hostname_uses_scanned_token_to_resolve_real_ip(self, get_mock, post_mock):
        cfx_response = FakeResponse(headers={"x-citizenfx-url": "https://node.example/"})
        endpoint_response = FakeResponse(payload=["203.0.113.25:30120"])
        get_mock.return_value = cfx_response
        post_mock.return_value = endpoint_response

        result = auto.resolve_server_endpoint(
            "https://cfx.re/join/example",
            token="scanned-token",
        )

        self.assertEqual(result, {
            "address": "203.0.113.25:30120",
            "base_urls": ["https://203.0.113.25:30120"],
        })
        post_mock.assert_called_once_with(
            "https://node.example/client",
            data={"method": "getEndpoints", "token": "scanned-token"},
            headers={"User-Agent": "CitizenFX/1"},
            timeout=15,
            verify=False,
        )
        self.assertTrue(endpoint_response.closed)

    @mock.patch("auto.requests.post")
    @mock.patch("auto.requests.get")
    def test_cfx_hostname_without_token_fails_before_post(self, get_mock, post_mock):
        get_mock.return_value = FakeResponse(headers={"x-citizenfx-url": "https://node.example:30120"})

        with self.assertRaisesRegex(RuntimeError, "无法获取 FiveM token"):
            auto.resolve_server_endpoint("https://cfx.re/join/example")

        post_mock.assert_not_called()

    @mock.patch("auto.requests.post")
    @mock.patch("auto.requests.get")
    def test_cfx_ip_keeps_existing_resolution_without_get_endpoints(self, get_mock, post_mock):
        get_mock.return_value = FakeResponse(headers={"x-citizenfx-url": "https://203.0.113.25:30120"})

        result = auto.resolve_server_endpoint("https://cfx.re/join/example", token="scanned-token")

        self.assertEqual(result["address"], "203.0.113.25:30120")
        self.assertEqual(result["base_urls"], ["https://203.0.113.25:30120"])
        post_mock.assert_not_called()

if __name__ == "__main__":
    unittest.main()
