from __future__ import annotations

from pathlib import Path
import smtplib
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from rds_mail import MailDeliveryError, send_reports


class MailTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.files = []
        for name in ("账号一-2026-11-03.pdf", "账号二-2026-11-03.pdf"):
            path = self.directory / name
            path.write_bytes(b"%PDF-1.4\nexample fixture")
            self.files.append(path)
        self.config = {
            "SMTP_HOST": "smtp.example.com", "SMTP_PORT": 465,
            "SMTP_USERNAME": "audit@example.com", "SMTP_AUTH_CODE": "private-auth-code",
            "MAIL_RECIPIENTS": ["recipient@example.com", "recipient@example.com"],
            "MAIL_CC": ["copy@example.com", "RECIPIENT@example.com"],
            "MAIL_SUBJECT": "AW-RDS审计报告", "MAIL_SENDER_NAME": "审计系统",
        }

    def server(self):
        smtp = MagicMock()
        smtp.ehlo.return_value = (250, b"hello")
        smtp.send_message.return_value = {}
        return smtp

    @patch("rds_mail.smtplib.SMTP_SSL")
    def test_ssl_one_message_contains_all_pdfs_and_cc_envelope(self, constructor):
        smtp = self.server()
        constructor.return_value = smtp
        result = send_reports(self.config, self.files, "两个账号的汇总见附件。")
        self.assertTrue(result["smtp_accepted"])
        self.assertEqual(result["attachment_count"], 2)
        self.assertEqual(result["recipients"], ["recipient@example.com", "copy@example.com"])
        constructor.assert_called_once()
        context = constructor.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        smtp.login.assert_called_once_with("audit@example.com", "private-auth-code")
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(message["Subject"], "AW-RDS审计报告")
        self.assertEqual(message["Cc"], "copy@example.com")
        self.assertEqual(smtp.send_message.call_args.kwargs["to_addrs"], result["recipients"])
        attachments = list(message.iter_attachments())
        self.assertEqual([part.get_filename() for part in attachments], [path.name for path in self.files])
        self.assertTrue(all(part.get_content_type() == "application/pdf" for part in attachments))
        self.assertNotIn("private-auth-code", message.as_string())
        smtp.quit.assert_called_once()
        smtp.close.assert_called_once()

    @patch("rds_mail.smtplib.SMTP")
    @patch("rds_mail.smtplib.SMTP_SSL")
    def test_starttls_before_login(self, secure_constructor, constructor):
        smtp = self.server()
        constructor.return_value = smtp
        send_reports({**self.config, "SMTP_SECURITY": "starttls", "SMTP_PORT": 587}, self.files, "body", "日期报告")
        secure_constructor.assert_not_called()
        self.assertEqual(smtp.ehlo.call_count, 2)
        calls = [call[0] for call in smtp.mock_calls]
        self.assertLess(calls.index("starttls"), calls.index("login"))
        self.assertTrue(smtp.starttls.call_args.kwargs["context"].check_hostname)

    @patch("rds_mail.smtplib.SMTP_SSL")
    def test_partial_refusal_is_uncertain_and_never_success(self, constructor):
        smtp = self.server()
        smtp.send_message.return_value = {"copy@example.com": (550, b"refused private-auth-code")}
        constructor.return_value = smtp
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(self.config, self.files, "body")
        self.assertTrue(failure.exception.delivery_uncertain)
        self.assertEqual(failure.exception.refused, ["copy@example.com"])
        self.assertNotIn("private-auth-code", str(failure.exception))

    @patch("rds_mail.smtplib.SMTP_SSL")
    def test_auth_errors_are_sanitized(self, constructor):
        smtp = self.server()
        smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, b"bad private-auth-code")
        constructor.return_value = smtp
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(self.config, self.files, "body")
        self.assertFalse(failure.exception.delivery_uncertain)
        self.assertNotIn("private-auth-code", str(failure.exception))
        smtp.send_message.assert_not_called()
        smtp.close.assert_called_once()

    @patch("rds_mail.smtplib.SMTP_SSL")
    def test_submission_disconnect_is_uncertain(self, constructor):
        smtp = self.server()
        smtp.send_message.side_effect = smtplib.SMTPServerDisconnected("private-auth-code")
        constructor.return_value = smtp
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(self.config, self.files, "body")
        self.assertTrue(failure.exception.delivery_uncertain)
        self.assertNotIn("private-auth-code", str(failure.exception))

    @patch("rds_mail.smtplib.SMTP_SSL")
    def test_quit_failure_after_acceptance_does_not_repeat_mail(self, constructor):
        smtp = self.server()
        smtp.quit.side_effect = smtplib.SMTPServerDisconnected("closed")
        constructor.return_value = smtp
        self.assertTrue(send_reports(self.config, self.files, "body")["smtp_accepted"])
        smtp.send_message.assert_called_once()
        smtp.close.assert_called_once()

    @patch("rds_mail.smtplib.SMTP_SSL")
    def test_all_recipients_refused_is_certain_failure(self, constructor):
        smtp = self.server()
        smtp.send_message.side_effect = smtplib.SMTPRecipientsRefused({"recipient@example.com": (550, b"private-auth-code")})
        constructor.return_value = smtp
        with self.assertRaises(MailDeliveryError) as failure:
            send_reports(self.config, self.files, "body")
        self.assertFalse(failure.exception.delivery_uncertain)
        self.assertNotIn("private-auth-code", str(failure.exception))

    @patch("rds_mail.smtplib.SMTP_SSL")
    def test_reject_header_injection_before_connecting(self, constructor):
        for key, bad in (("MAIL_SUBJECT", "ok\nBcc: attacker@example.com"),
                         ("MAIL_SENDER_NAME", "Audit\r\nBcc: attacker@example.com"),
                         ("MAIL_RECIPIENTS", ["ok@example.com\nBcc: attacker@example.com"]),
                         ("MAIL_CC", ["A <a@example.com>"])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                send_reports({**self.config, key: bad}, self.files, "body")
        constructor.assert_not_called()

    @patch("rds_mail.smtplib.SMTP_SSL")
    def test_reject_insecure_or_missing_settings_and_non_pdf(self, constructor):
        for changes in ({"SMTP_SECURITY": "none"}, {"SMTP_PORT": True}, {"SMTP_TIMEOUT": -1},
                        {"MAIL_RECIPIENTS": []}, {"SMTP_AUTH_CODE": ""}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                send_reports({**self.config, **changes}, self.files, "body")
        self.files[0].write_bytes(b"not a PDF")
        with self.assertRaises(ValueError):
            send_reports(self.config, self.files, "body")
        constructor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
