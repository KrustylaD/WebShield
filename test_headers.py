
import unittest


from scanner import (
    SECURITY_HEADERS,
    check_header,
    parse_directives,
    scan_headers,
    _parse_max_age,
)



class TestSecurityHeaders(unittest.TestCase):

    def get_header(self, header_name):
        return next(
            item for item in SECURITY_HEADERS
            if item["header"] == header_name
        )

    def test_csp_empty_policy(self):
        item = self.get_header("Content-Security-Policy")
        result = check_header(
            item,
            {"Content-Security-Policy": ""},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

   
def test_csp_with_directive_is_detected(self):
    item = self.get_header("Content-Security-Policy")
    result = check_header(
        item,
        {"Content-Security-Policy": "default-src 'self'"},
        True,
    )

    self.assertEqual(result["status"], "À_AMÉLIORER")
    self.assertIn("Score heuristique CSP", result["details"])


    def test_permissions_policy_invalid_value(self):
        item = self.get_header("Permissions-Policy")
        result = check_header(
            item,
            {"Permissions-Policy": ""},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

    def test_x_frame_options_invalid_value(self):
        item = self.get_header("X-Frame-Options")
        result = check_header(
            item,
            {"X-Frame-Options": "ALLOW-FROM https://example.com"},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

    def test_x_content_type_options_invalid_value(self):
        item = self.get_header("X-Content-Type-Options")
        result = check_header(
            item,
            {"X-Content-Type-Options": "invalid"},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

    def test_hsts_not_conformant_over_http(self):
        item = self.get_header("Strict-Transport-Security")
        result = check_header(
            item,
            {"Strict-Transport-Security": "max-age=31536000"},
            False,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

    def test_hsts_zero_max_age(self):
        item = self.get_header("Strict-Transport-Security")
        result = check_header(
            item,
            {"Strict-Transport-Security": "max-age=0"},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")


    def test_csp_malformed_directive_is_not_conformant(self):
        item = self.get_header("Content-Security-Policy")
        result = check_header(
            item,
            {"Content-Security-Policy": ";;;"},
            True,
        )
        self.assertNotEqual(result["status"], "CONFORME")


    def test_csp_directive_without_value_is_not_conformant(self):
        item = self.get_header("Content-Security-Policy")
        result = check_header(
            item,
            {"Content-Security-Policy": "default-src"},
            True,
        )
        self.assertNotEqual(result["status"], "CONFORME")

    def test_csp_unknown_directive_is_not_conformant(self):
        item = self.get_header("Content-Security-Policy")
        result = check_header(
            item,
            {"Content-Security-Policy": "totally-unknown value"},
            True,
        )
        self.assertNotEqual(result["status"], "CONFORME")


    def test_hsts_valid_max_age(self):
        item = self.get_header("Strict-Transport-Security")
        result = check_header(
            item,
            {"Strict-Transport-Security": "max-age=31536000"},
            True,
        )
        self.assertEqual(result["status"], "CONFORME")

    def test_hsts_invalid_max_age(self):
        item = self.get_header("Strict-Transport-Security")
        result = check_header(
            item,
            {"Strict-Transport-Security": "max-age=abc"},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

    def test_hsts_negative_max_age(self):
        item = self.get_header("Strict-Transport-Security")
        result = check_header(
            item,
            {"Strict-Transport-Security": "max-age=-1"},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

    def test_hsts_missing_max_age(self):
        item = self.get_header("Strict-Transport-Security")
        result = check_header(
            item,
            {"Strict-Transport-Security": "includeSubDomains"},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")


    def test_hsts_duplicate_max_age(self):
        item = self.get_header("Strict-Transport-Security")
        result = check_header(
            item,
            {"Strict-Transport-Security": "max-age=31536000; max-age=0"},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

    def test_hsts_empty_max_age(self):
        item = self.get_header("Strict-Transport-Security")
        result = check_header(
            item,
            {"Strict-Transport-Security": "max-age="},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

    def test_hsts_non_ascii_digits(self):
        item = self.get_header("Strict-Transport-Security")
        result = check_header(
            item,
            {"Strict-Transport-Security": "max-age=１２３"},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

    def test_hsts_with_include_subdomains(self):
        item = self.get_header("Strict-Transport-Security")
        result = check_header(
            item,
            {
                "Strict-Transport-Security":
                    "max-age=31536000; includeSubDomains"
            },
            True,
        )
        self.assertEqual(result["status"], "CONFORME")


    def test_hsts_is_not_compliant_on_http(self):
        item = next(
            item for item in SECURITY_HEADERS
            if item["header"] == "Strict-Transport-Security"
        )
        result = check_header(
            item,
            {"Strict-Transport-Security": "max-age=31536000"},
            False,
        )
        self.assertEqual(result["status"], "A_VERIFIER")

    def test_empty_response_list_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_headers([])

    def test_max_age_zero_is_not_compliant(self):
        self.assertEqual(_parse_max_age("max-age=0"), 0)
        item = next(
            item for item in SECURITY_HEADERS
            if item["header"] == "Strict-Transport-Security"
        )
        result = check_header(
            item,
            {"Strict-Transport-Security": "max-age=0"},
            True,
        )
        self.assertEqual(result["status"], "A_VERIFIER")


if __name__ == "__main__":
    unittest.main(verbosity=2)
