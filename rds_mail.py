"""Send one message with the account PDFs; SMTP acceptance is not inbox delivery."""
from __future__ import annotations

from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, parseaddr
from pathlib import Path
import re
import smtplib
import ssl


class MailDeliveryError(RuntimeError):
    """A sanitized mail failure. Partial acceptance must not be silently retried."""

    def __init__(self, message, *, delivery_uncertain=False, refused=None):
        super().__init__(message)
        self.delivery_uncertain = delivery_uncertain
        self.refused = list(refused or [])


def _header(value, name, *, allow_empty=False):
    if not isinstance(value, str) or "\r" in value or "\n" in value:
        raise ValueError(f"{name} 必须为单行字符串")
    value = value.strip()
    if not value and not allow_empty:
        raise ValueError(f"请填写 {name}")
    return value


def _address(value, name):
    value = _header(value, name)
    _, parsed = parseaddr(value)
    if parsed != value or not re.fullmatch(r"[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+", value):
        raise ValueError(f"{name} 必须为邮箱地址，不含显示名称")
    return value


def _addresses(values, name, *, required=False):
    if not isinstance(values, list) or (required and not values):
        raise ValueError(f"{name} 必须为{'非空' if required else ''}邮箱地址数组")
    result, seen = [], set()
    for value in values:
        address = _address(value, name)
        if address.casefold() not in seen:
            seen.add(address.casefold())
            result.append(address)
    return result


def send_reports(config: dict, attachments: list[Path], body: str,
                 subject: str | None = None, *, html_body: str | None = None) -> dict:
    """Submit all account PDFs in one TLS-protected SMTP transaction.

    Failures expose only the operation stage and error class, never the provider's
    response body, credentials, or authorization code. A partial refusal raises
    MailDeliveryError(delivery_uncertain=True): some recipients may have received
    the message, so callers should retain the PDFs and flag manual verification.
    """
    host = _header(config.get("SMTP_HOST", ""), "SMTP_HOST")
    sender = _address(config.get("SMTP_USERNAME", ""), "SMTP_USERNAME")
    password = _header(config.get("SMTP_AUTH_CODE", ""), "SMTP_AUTH_CODE")
    sender_name = _header(config.get("MAIL_SENDER_NAME", ""), "MAIL_SENDER_NAME", allow_empty=True)
    mail_subject = _header(subject if subject is not None else config.get("MAIL_SUBJECT", "AW-RDS审计报告"), "MAIL_SUBJECT")
    recipients = _addresses(config.get("MAIL_RECIPIENTS", []), "MAIL_RECIPIENTS", required=True)
    cc = _addresses(config.get("MAIL_CC", []), "MAIL_CC")
    cc = [value for value in cc if value.casefold() not in {address.casefold() for address in recipients}]
    envelope = recipients + cc
    port = config.get("SMTP_PORT", 465)
    timeout = config.get("SMTP_TIMEOUT", 30)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("SMTP_PORT 必须为 1-65535 的整数")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 600:
        raise ValueError("SMTP_TIMEOUT 必须大于 0 且不超过 600 秒")
    security = config.get("SMTP_SECURITY", "ssl")
    if security not in ("ssl", "starttls"):
        raise ValueError("SMTP_SECURITY 仅支持 ssl 或 starttls")
    if not isinstance(body, str):
        raise ValueError("邮件正文必须为字符串")
    if html_body is not None and not isinstance(html_body, str):
        raise ValueError("HTML 邮件正文必须为字符串")
    if not attachments:
        raise ValueError("邮件至少需要一个 PDF 附件")

    message = EmailMessage()
    message["From"] = formataddr((sender_name, sender))
    message["To"] = ", ".join(recipients)
    if cc:
        message["Cc"] = ", ".join(cc)
    message["Subject"] = mail_subject
    message["Date"] = formatdate(localtime=False, usegmt=True)
    message["Message-ID"] = make_msgid()
    message.set_content(body)
    if html_body is not None:
        message.add_alternative(html_body, subtype="html")
    names = set()
    for item in attachments:
        path = Path(item)
        name = _header(path.name, "PDF 文件名")
        if name.casefold() in names:
            raise ValueError("PDF 附件文件名不能重复")
        names.add(name.casefold())
        content = path.read_bytes()
        if path.suffix.lower() != ".pdf" or not content.startswith(b"%PDF-"):
            raise ValueError("附件必须为 PDF 文件")
        message.add_attachment(content, maintype="application", subtype="pdf", filename=name)

    smtp = None
    stage = "连接邮件服务器"
    submitted = False
    try:
        context = ssl.create_default_context()
        if security == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        else:
            smtp = smtplib.SMTP(host, port, timeout=timeout)
        code, _ = smtp.ehlo()
        if code != 250:
            raise MailDeliveryError("邮件服务器 EHLO 未成功")
        if security == "starttls":
            stage = "建立 STARTTLS"
            smtp.starttls(context=context)
            code, _ = smtp.ehlo()
            if code != 250:
                raise MailDeliveryError("邮件服务器 TLS 后 EHLO 未成功")
        stage = "SMTP 认证"
        smtp.login(sender, password)
        stage = "提交邮件"
        submitted = True
        refused = smtp.send_message(message, from_addr=sender, to_addrs=envelope)
        if refused:
            raise MailDeliveryError("部分收件人被拒绝，其他收件人可能已收到；请核实后手动重发。",
                                    delivery_uncertain=True,
                                    refused=[address for address in envelope if address in refused])
        return {"smtp_accepted": True, "recipients": envelope,
                "message_id": str(message["Message-ID"]), "attachment_count": len(attachments)}
    except smtplib.SMTPRecipientsRefused:
        raise MailDeliveryError("邮件服务器拒绝所有收件人；PDF 已保留。") from None
    except (OSError, smtplib.SMTPException) as exc:
        raise MailDeliveryError(f"{stage}失败（{type(exc).__name__}）；PDF 已保留。",
                                delivery_uncertain=submitted) from None
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except (OSError, smtplib.SMTPException):
                pass
            finally:
                try:
                    smtp.close()
                except (OSError, smtplib.SMTPException):
                    pass
