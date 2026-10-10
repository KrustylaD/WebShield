
import json
import os
import tempfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch, MagicMock

import report
from report import calculate_coverage, generate_html_report


class TestCoverage(unittest.TestCase):

    def test_empty_results(self):
        self.assertEqual(calculate_coverage([]), 0)

    def test_all_headers_compliant(self):
        results = [
            {"status": "CONFORME", "weight": 20},
            {"status": "CONFORME", "weight": 80},
        ]
        self.assertEqual(calculate_coverage(results), 100)

    def test_all_headers_missing(self):
        results = [
            {"status": "NON_DETECTE", "weight": 20},
            {"status": "NON_DETECTE", "weight": 80},
        ]
        self.assertEqual(calculate_coverage(results), 0)

    def test_all_headers_need_review(self):
        results = [{"status": "A_VERIFIER", "weight": 100}]
        self.assertEqual(calculate_coverage(results), 50)

    def test_csp_weak_status_is_supported(self):
        results = [{"status": "FAIBLE", "weight": 100}]
        self.assertEqual(calculate_coverage(results), 0)

    def test_csp_quality_statuses_are_scored(self):
        results = [
            {
                "status": "CONFIGURATION_APPAREMMENT_SOLIDE",
                "weight": 50,
            },
            {"status": "À_AMÉLIORER", "weight": 50},
        ]
        self.assertEqual(calculate_coverage(results), 75)

    def test_weighted_score(self):
        results = [
            {"status": "CONFORME", "weight": 75},
            {"status": "NON_DETECTE", "weight": 25},
        ]
        self.assertEqual(calculate_coverage(results), 75)

    def test_unknown_status_is_rejected(self):
        with self.assertRaises(ValueError):
            calculate_coverage([
                {"status": "STATUT_INCONNU", "weight": 100}
            ])

    def test_negative_weight_is_rejected(self):
        with self.assertRaises(ValueError):
            calculate_coverage([
                {"status": "CONFORME", "weight": -10}
            ])

    
    def test_boolean_weight_is_rejected(self):
        with self.assertRaises(ValueError):
            calculate_coverage([
                {"status": "CONFORME", "weight": True}
            ])

    def test_non_numeric_weight_is_rejected(self):
        with self.assertRaises(ValueError):
            calculate_coverage([
                {"status": "CONFORME", "weight": "100"}
            ])

    def test_zero_total_weight_returns_zero(self):
        self.assertEqual(
            calculate_coverage([
                {"status": "CONFORME", "weight": 0}
            ]),
            0,
        )
        


class TestHTMLReport(unittest.TestCase):

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.output_path = Path(self.temp_dir.name) / "test_report.html"
        self.response = MagicMock()
        self.response.url = "https://example.test/"
        self.response.status_code = 200

        self.patcher = patch.object(
            report, "REPORT_FILE", str(self.output_path)
        )
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.temp_dir.cleanup()

    def generate_report(self, url="https://example.test/"):
        return generate_html_report(
            url=url,
            final_response=self.response,
            header_results=[
                {
                    "name": "Content-Security-Policy",
                    "status": "CONFORME",
                    "weight": 25,
                    "details": "Politique présente",
                    "recommendation": "Vérifier sa qualité",
                }
            ],
            cookie_results=[],
            redirect_results=[],
            coverage_score=100,
        )

    def test_report_file_is_created(self):
        result = self.generate_report()
        self.assertTrue(Path(result).is_file())

    def test_report_contains_score_and_summary(self):
        self.generate_report()
        html = self.output_path.read_text(encoding="utf-8")

        self.assertIn("100/100", html)
        self.assertIn("Couverture indicative", html)
        self.assertIn("ne prouve pas l'absence de vulnérabilités", html)

    def test_url_is_html_escaped(self):
        self.generate_report(
            'https://example.test/?q=<script>alert("x")</script>'
        )
        html = self.output_path.read_text(encoding="utf-8")

        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)

    def test_header_details_are_html_escaped(self):
        generate_html_report(
            url="https://example.test/",
            final_response=self.response,
            header_results=[
                {
                    "name": "CSP",
                    "status": "CONFORME",
                    "weight": 25,
                    "details": "<script>alert(1)</script>",
                    "recommendation": "<img src=x>",
                }
            ],
            cookie_results=[],
            redirect_results=[],
            coverage_score=100,
        )
        html = self.output_path.read_text(encoding="utf-8")

        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img", html)

    
    def test_cookie_fields_are_html_escaped(self):
        generate_html_report(
            url="https://example.test/",
            final_response=self.response,
            header_results=[],
            cookie_results=[
                {
                    "name": '<script>alert("cookie")</script>',
                    "status": "A_VERIFIER",
                    "secure": False,
                    "httponly": False,
                    "samesite": '<img src=x onerror=alert(1)>',
                    "details": "<script>alert(2)</script>",
                }
            ],
            redirect_results=[],
            coverage_score=0,
        )

        html = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn('<script>alert("cookie")</script>', html)
        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img", html)

    def test_redirect_url_is_html_escaped(self):
        malicious_url = (
            'https://example.test/<img src=x onerror=alert(1)>'
        )

        generate_html_report(
            url="https://example.test/",
            final_response=self.response,
            header_results=[],
            cookie_results=[],
            redirect_results=[
                {
                    "step": 1,
                    "url": malicious_url,
                    "status_code": 200,
                    "https": True,
                    "hsts": False,
                    "csp": False,
                    "csp_report_only": False,
                    "x_content_type_options": False,
                    "x_frame_options": False,
                }
            ],
            coverage_score=0,
        )

        html = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn(malicious_url, html)
        self.assertIn("&lt;img", html)


class TestJSONReport(unittest.TestCase):
    def test_json_round_trip(self):
        data = {
            "tool": "WebShield V5",
            "coverage_score": 20,
            "url_final": "https://example.test/",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "report.json")

            with open(path, "w", encoding="utf-8") as file:
                json.dump(data, file, ensure_ascii=False, indent=4)

            with open(path, "r", encoding="utf-8") as file:
                loaded = json.load(file)

        self.assertEqual(loaded["tool"], "WebShield V5")
        self.assertEqual(loaded["coverage_score"], 20)
        self.assertEqual(loaded["url_final"], "https://example.test/")

    def test_json_preserves_accents(self):
        data = {"message": "Sécurité vérifiée"}

        serialized = json.dumps(data, ensure_ascii=False)
        loaded = json.loads(serialized)

        self.assertEqual(loaded["message"], "Sécurité vérifiée")


if __name__ == "__main__":
    unittest.main(verbosity=2)
