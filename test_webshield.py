
import unittest
from unittest.mock import patch, MagicMock

import requests
import scanner
from scanner import fetch_responses


class TestWebShieldRedirects(unittest.TestCase):

    def make_response(self, status_code, location=None):
        response = MagicMock()
        response.status_code = status_code
        response.headers = {}
        response.url = "https://public.example/"

        if location is not None:
            response.headers["Location"] = location

        return response

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_refuses_private_redirect(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value
        response = self.make_response(
            302, "http://127.0.0.1/admin"
        )
        session.get.return_value = response

        def validate_side_effect(url):
            if "127.0.0.1" in url:
                raise ValueError("Destination privée interdite.")

        mock_validate.side_effect = validate_side_effect

        with self.assertRaises(ValueError):
            fetch_responses("https://public.example/")

        self.assertEqual(session.get.call_count, 1)
        response.close.assert_called_once()

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_follows_public_redirect(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value

        redirect_response = self.make_response(
            302, "https://public.example/final"
        )
        final_response = self.make_response(200)

        session.get.side_effect = [redirect_response, final_response]

        result, responses = fetch_responses(
            "https://public.example/"
        )

        self.assertIs(result, final_response)
        self.assertEqual(len(responses), 2)
        self.assertEqual(session.get.call_count, 2)
        self.assertTrue(mock_validate.called)

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_refuses_too_many_redirects(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value

        session.get.return_value = self.make_response(
            302, "https://public.example/next"
        )

        with self.assertRaises(requests.TooManyRedirects):
            fetch_responses("https://public.example/")

        self.assertEqual(
            session.get.call_count,
            11,  # MAX_REDIRECTS + 1, selon la configuration actuelle
        )

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_redirect_without_location_returns_response(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value
        response = self.make_response(302)
        session.get.return_value = response

        result, responses = fetch_responses(
            "https://public.example/"
        )

        self.assertIs(result, response)
        self.assertEqual(len(responses), 1)
        self.assertEqual(session.get.call_count, 1)

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_refuses_declared_oversized_response(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value
        response = self.make_response(200)
        response.headers["Content-Length"] = str(
            scanner.MAX_RESPONSE_BYTES + 1
        )
        session.get.return_value = response

        with self.assertRaisesRegex(ValueError, "trop volumineuse"):
            fetch_responses("https://public.example/")

        response.close.assert_called_once()

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_refuses_oversized_stream_without_content_length(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value
        response = self.make_response(200)
        response.headers.pop("Content-Length", None)
        response.iter_content.return_value = [
            b"x" * scanner.MAX_RESPONSE_BYTES,
            b"overflow",
        ]
        session.get.return_value = response

        with self.assertRaisesRegex(ValueError, "après lecture"):
            fetch_responses("https://public.example/")

        response.close.assert_called_once()

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_closes_previous_responses_after_error(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value

        redirect_response = self.make_response(
            302, "https://public.example/next"
        )
        session.get.return_value = redirect_response

        def validate_side_effect(url):
            if url.endswith("/next"):
                raise ValueError("Destination refusée.")

        mock_validate.side_effect = validate_side_effect

        with self.assertRaises(ValueError):
            fetch_responses("https://public.example/")

        redirect_response.close.assert_called_once()
        self.assertEqual(session.get.call_count, 1)

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_clears_auth_on_host_change(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value

        redirect_response = self.make_response(
            302, "https://other.example/final"
        )
        final_response = self.make_response(200)

        session.get.side_effect = [redirect_response, final_response]
        session.auth = ("user", "password")

        result, responses = fetch_responses(
            "https://public.example/"
        )

        self.assertIs(result, final_response)
        self.assertIsNone(session.auth)
        self.assertEqual(len(responses), 2)

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_does_not_clear_auth_on_same_host(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value

        redirect_response = self.make_response(
            302, "https://public.example/final"
        )
        final_response = self.make_response(200)

        session.get.side_effect = [redirect_response, final_response]
        session.auth = ("user", "password")

        result, responses = fetch_responses(
            "https://public.example/"
        )

        self.assertIs(result, final_response)
        self.assertEqual(session.auth, ("user", "password"))
        self.assertEqual(len(responses), 2)


    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_network_error_propagates(self, mock_validate, mock_session_class):
        session = mock_session_class.return_value.__enter__.return_value
        session.get.side_effect = requests.ConnectionError("Connexion refusée")

        with self.assertRaises(requests.ConnectionError):
            fetch_responses("https://public.example/")

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_timeout_propagates(self, mock_validate, mock_session_class):
        session = mock_session_class.return_value.__enter__.return_value
        session.get.side_effect = requests.Timeout("Délai dépassé")

        with self.assertRaises(requests.Timeout):
            fetch_responses("https://public.example/")

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_redirect_to_other_scheme_is_validated(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value
        redirect = self.make_response(302, "http://public.example/final")
        final = self.make_response(200)
        session.get.side_effect = [redirect, final]

        result, responses = fetch_responses("https://public.example/")

        self.assertIs(result, final)
        self.assertEqual(len(responses), 2)
        validated_urls = [call.args[0] for call in mock_validate.call_args_list]
        self.assertIn("http://public.example/final", validated_urls)

    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_closes_responses_when_network_error_occurs_after_redirect(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value
        redirect = self.make_response(302, "https://public.example/next")
        session.get.side_effect = [
            redirect,
            requests.ConnectionError("Connexion interrompue"),
        ]

        with self.assertRaises(requests.ConnectionError):
            fetch_responses("https://public.example/")

        redirect.close.assert_called_once()

    
    @patch("scanner.requests.Session")
    @patch("scanner.validate_public_destination")
    def test_closes_all_responses_after_successful_scan(
        self, mock_validate, mock_session_class
    ):
        session = mock_session_class.return_value.__enter__.return_value

        redirect = self.make_response(
            302, "https://public.example/final"
        )
        final = self.make_response(200)
        session.get.side_effect = [redirect, final]

        _, responses = fetch_responses("https://public.example/")

        self.assertEqual(len(responses), 2)

        # fetch_responses renvoie les réponses à l'appelant :
        # c'est main() qui doit les fermer après leur analyse.
        redirect.close.assert_not_called()
        final.close.assert_not_called()

    @patch("scanner.socket.getaddrinfo")
    def test_rejects_hostname_resolving_to_private_ip(self, mock_dns):
        mock_dns.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 80))
        ]

        from scanner import validate_http_url

        with self.assertRaises(ValueError):
            validate_http_url("http://internal.example/")

    @patch("scanner.socket.getaddrinfo")
    def test_rejects_hostname_with_mixed_public_and_private_ips(
        self, mock_dns
    ):
        mock_dns.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 80)),
            (2, 1, 6, "", ("192.168.1.10", 80)),
        ]

        from scanner import validate_http_url

        with self.assertRaises(ValueError):
            validate_http_url("http://mixed.example/")

    def test_refuses_url_with_credentials(self):
        from scanner import validate_http_url

        with self.assertRaises(ValueError):
            validate_http_url(
                "https://user:password@example.com/"
            )


from unittest.mock import Mock, patch
import unittest

import main


class TestResponseCleanup(unittest.TestCase):

    @patch("main.fetch_responses")
    @patch("main.input", return_value="https://example.com")
    def test_responses_are_closed_after_successful_analysis(
        self, mock_input, mock_fetch
    ):
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        mock_fetch.return_value = (response, [response])

        with patch("main.scan_headers", return_value=[]), \
             patch("main.scan_cookies", return_value=[]), \
             patch("main.scan_redirects", return_value=[]), \
             patch("main.calculate_coverage", return_value=0), \
             patch("main.generate_html_report", return_value="report.html"):
            main.main()

        response.close.assert_called_once()

    @patch("main.fetch_responses")
    @patch("main.input", return_value="https://example.com")
    def test_responses_are_closed_if_header_scan_fails(
        self, mock_input, mock_fetch
    ):
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        mock_fetch.return_value = (response, [response])

        with patch(
            "main.scan_headers",
            side_effect=RuntimeError("erreur de test"),
        ):
            with self.assertRaisesRegex(RuntimeError, "erreur de test"):
                main.main()

        response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
