import unittest

from packet_sniffer import (
    redact_email,
    redact_sensitive_values,
    mask_ip,
    redact_text
)


class TestRedaction(unittest.TestCase):

    def test_email_redaction(self):
        text = "Contact test@example.com for information."
        result = redact_email(text)

        self.assertNotIn("test@example.com", result)
        self.assertIn("[REDACTED_EMAIL]", result)

    def test_password_redaction(self):
        text = "username=student&password=secret123"
        result = redact_sensitive_values(text)

        self.assertNotIn("secret123", result)
        self.assertIn("[REDACTED]", result)

    def test_token_redaction(self):
        text = "token=ABC123456"
        result = redact_sensitive_values(text)

        self.assertNotIn("ABC123456", result)
        self.assertIn("[REDACTED]", result)

    def test_cookie_redaction(self):
        text = "Cookie: sessionid=ABC123"
        result = redact_sensitive_values(text)

        self.assertNotIn("ABC123", result)
        self.assertIn("[REDACTED]", result)

    def test_ipv4_masking(self):
        result = mask_ip("192.168.1.177")

        self.assertEqual(result, "192.168.1.xxx")

    def test_ipv6_masking(self):
        result = mask_ip(
            "2606:4700:4408:ac40:9bd1:1234:5678:abcd"
        )

        self.assertTrue(result.endswith(":xxxx"))

    def test_combined_redaction(self):
        text = "Email test@example.com password=secret token=ABC123"
        result = redact_text(text)

        self.assertNotIn("test@example.com", result)
        self.assertNotIn("secret", result)
        self.assertNotIn("ABC123", result)


if __name__ == "__main__":
    unittest.main()