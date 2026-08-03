from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Any


class EmailNotificationError(RuntimeError):
    pass


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _split_recipients(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _default_email_config() -> dict[str, Any]:
    return {
        "enabled": False,
        "host": "",
        "port": 587,
        "username": "",
        "password": "",
        "from_address": "",
        "to_addresses": "",
        "use_tls": True,
        "use_ssl": False,
        "subject_prefix": "[infra-sync-api]",
    }


def normalize_email_config(raw: dict[str, Any] | None) -> dict[str, Any]:
    config = _default_email_config()
    if not isinstance(raw, dict):
        return config

    config["enabled"] = bool(raw.get("enabled", config["enabled"]))
    config["host"] = _normalize_text(raw.get("host", config["host"]))
    config["username"] = _normalize_text(raw.get("username", config["username"]))
    config["password"] = _normalize_text(raw.get("password", config["password"]))
    config["from_address"] = _normalize_text(raw.get("from_address", config["from_address"]))
    config["to_addresses"] = _normalize_text(raw.get("to_addresses", config["to_addresses"]))
    config["subject_prefix"] = _normalize_text(raw.get("subject_prefix", config["subject_prefix"])) or config["subject_prefix"]
    config["use_tls"] = bool(raw.get("use_tls", config["use_tls"]))
    config["use_ssl"] = bool(raw.get("use_ssl", config["use_ssl"]))
    try:
        config["port"] = max(1, int(str(raw.get("port", config["port"])).strip()))
    except (TypeError, ValueError):
        config["port"] = config["port"]

    if config["use_ssl"]:
        config["use_tls"] = False
    return config


def build_alert_digest(alerts: list[dict[str, Any]], *, source: str = "Zabbix") -> tuple[str, str]:
    rows = []
    lines = [f"Alertas ativos em {source}", ""]
    if not alerts:
        lines.append("Nenhum alerta aberto no momento.")
        html_rows = "<tr><td colspan=\"4\">Nenhum alerta aberto no momento.</td></tr>"
    else:
        for alert in alerts:
            hosts = alert.get("hosts") if isinstance(alert.get("hosts"), list) else []
            host = hosts[0] if hosts else {}
            host_name = _normalize_text(host.get("name") or host.get("host") or host.get("hostid") or "—")
            name = _normalize_text(alert.get("name") or "—")
            severity = _normalize_text(alert.get("severity") or "—")
            clock = _normalize_text(alert.get("clock") or "—")
            lines.append(f"- {name} | {severity} | {host_name} | {clock}")
            rows.append(
                f"<tr><td>{name}</td><td>{severity}</td><td>{host_name}</td><td>{clock}</td></tr>"
            )
        html_rows = "".join(rows)

    text = "\n".join(lines)
    html = f"""
    <html>
      <body style="font-family:Arial,sans-serif;background:#111;color:#f5f5f5;padding:24px;">
        <h2 style="margin-top:0;">Alertas ativos em {source}</h2>
        <table cellpadding="8" cellspacing="0" border="0" style="border-collapse:collapse;width:100%;background:#1a1a1f;">
          <thead>
            <tr><th align="left">Problema</th><th align="left">Severidade</th><th align="left">Host</th><th align="left">Clock</th></tr>
          </thead>
          <tbody>{html_rows}</tbody>
        </table>
      </body>
    </html>
    """
    return text, html


def send_alert_email(
    email_config: dict[str, Any],
    alerts: list[dict[str, Any]],
    *,
    source: str = "Zabbix",
) -> dict[str, Any]:
    config = normalize_email_config(email_config)
    if not config["enabled"]:
        raise EmailNotificationError("Email notifications are disabled")
    if not config["host"]:
        raise EmailNotificationError("SMTP host is required")

    recipients = _split_recipients(config["to_addresses"])
    if not recipients:
        raise EmailNotificationError("At least one recipient is required")

    from_address = config["from_address"] or config["username"] or recipients[0]
    text_body, html_body = build_alert_digest(alerts, source=source)
    subject = f"{config['subject_prefix']} {source} alertas ativos".strip()

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_address
    message["To"] = ", ".join(recipients)
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")

    context = ssl.create_default_context()
    if config["use_ssl"]:
        with smtplib.SMTP_SSL(config["host"], config["port"], context=context, timeout=30) as server:
            _login_and_send(server, config, from_address, recipients, message)
    else:
        with smtplib.SMTP(config["host"], config["port"], timeout=30) as server:
            server.ehlo()
            if config["use_tls"]:
                server.starttls(context=context)
                server.ehlo()
            _login_and_send(server, config, from_address, recipients, message)

    return {
        "subject": subject,
        "from": from_address,
        "recipients": recipients,
        "alerts": len(alerts),
    }


def _login_and_send(
    server: smtplib.SMTP | smtplib.SMTP_SSL,
    config: dict[str, Any],
    from_address: str,
    recipients: list[str],
    message: EmailMessage,
) -> None:
    if config["username"]:
        server.login(config["username"], config["password"])
    server.send_message(message, from_addr=from_address, to_addrs=recipients)
