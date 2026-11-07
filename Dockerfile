# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/userreksai/aws-rds-audit" \
      org.opencontainers.image.title="AWS RDS source IP audit"

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 TZ=Asia/Shanghai HOME=/root \
    VIRTUAL_ENV=/app/.venv PATH="/app/.venv/bin:$PATH"
WORKDIR /app
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates fonts-wqy-zenhei tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && chmod 0755 /root
COPY requirements.txt /app/requirements.txt
RUN python -m venv /app/.venv && /app/.venv/bin/python -m pip install -r /app/requirements.txt
# Explicit production allowlist. Never copy private settings, reports or checkout.
COPY rds_audit.py rds_cache.py rds_change_filter.py rds_config.py rds_daily_mail.py \
     rds_failure_alerts.py rds_mail.py rds_multi.py rds_pdf.py rds_retention.py \
     rds_summary.py rds_report.py rds_window.py rds_mail_summary.py rds_schedule.py lark_notify.py rds-audit-config.example.json /app/
COPY deploy/docker_runtime.py deploy/docker_config.py /app/deploy/
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["/app/.venv/bin/python", "/app/deploy/docker_runtime.py", "healthcheck"]
ENTRYPOINT ["/app/.venv/bin/python", "/app/deploy/docker_runtime.py"]
CMD ["schedule"]
