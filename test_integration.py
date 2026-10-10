
"""Tests d'intégration locaux de WebShield."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import unittest

import requests
import scanner


class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=()")
        self.send_header(
            "Set-Cookie",
            "session=fake; HttpOnly; SameSite=Strict",
        )
        self.end_headers()
        self.wfile.write(b"WebShield local test")

    def log_message(self, format, *args):
        pass


class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.server = HTTPServer(("127.0.0.1", 0), TestHandler)
        self.port = self.server.server_address[1]
        self.thread = Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_local_server_headers(self):
        response = requests.get(
            f"http://127.0.0.1:{self.port}/",
            timeout=3,
        )

        try:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response.headers.get("X-Frame-Options"),
                "DENY",
            )
            self.assertIn(
                "session=fake",
                response.headers.get("Set-Cookie", ""),
            )
        finally:
            response.close()

    def test_webshield_analysis_on_local_response(self):
        response = requests.get(
            f"http://127.0.0.1:{self.port}/",
            timeout=3,
        )

        try:
            header_results = scanner.scan_headers([response])
            cookie_results = scanner.scan_cookies([response])
            redirect_results = scanner.scan_redirects([response])

            self.assertTrue(header_results)
            self.assertTrue(cookie_results)
            self.assertTrue(redirect_results)

            header_names = {
                item.get("header") for item in header_results
            }

            self.assertIn("Content-Security-Policy", header_names)
            self.assertIn("X-Frame-Options", header_names)
        finally:
            response.close()


if __name__ == "__main__":
    unittest.main()
