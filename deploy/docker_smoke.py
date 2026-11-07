#!/usr/bin/env python3
"""Run inside the built production image with fake SQL/SMTP and no network."""
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
import sys
import tempfile
from unittest.mock import Mock, patch

sys.path.insert(0, '/app' if Path('/app/rds_multi.py').is_file() else str(Path(__file__).resolve().parent.parent))
import rds_multi as multi
from rds_config import ACCOUNT_DEFAULTS, DEFAULTS
from rds_summary import SummaryAccumulator


def main():
    output = Path(sys.argv[1] if len(sys.argv) > 1 else '/data')
    config = {**deepcopy(DEFAULTS), 'OUTPUT_DIRECTORY': str(output),
              'TIMEZONE': 'Asia/Shanghai', 'SMTP_HOST': 'smtp.example.invalid',
              'SMTP_USERNAME': 'sender@example.invalid', 'SMTP_AUTH_CODE': 'FICTIONAL-AUTH',
              'MAIL_RECIPIENTS': ['recipient@example.invalid'], 'MAIL_CC': ['copy@example.invalid'],
              'ACCOUNTS': [{**ACCOUNT_DEFAULTS, 'NAME': 'offline-' + str(index),
                            'ACCOUNT_ID': f'{index:012}', 'TAG': '测试账号', 'REGIONS': 'us-east-1'}
                           for index in (1, 2)]}
    day = date(2026, 11, 6)
    start = datetime(2026, 11, 5, 2, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    reports = []
    for account in config['ACCOUNTS']:
        with tempfile.TemporaryDirectory() as temporary:
            with SummaryAccumulator(temporary, start, end, dimension='ip') as accumulator:
                event = {'region': 'us-east-1', 'logGroupName': '/aws/rds/cluster/offline/audit',
                         'logStreamName': 'writer', 'timestamp': int(start.timestamp() * 1000),
                         'eventId': 'fictional-event',
                         'message': f"{int(start.timestamp() * 1000000)},writer,app,192.0.2.22,99,23,QUERY,db,'UPDATE t SET n=1',0"}
                accumulator.process_audit(event)
                summary = accumulator.finish()
        assert summary['actors'] and summary['actors'][0]['counts']['修改'] == 1
        reports.append({**summary, 'account_id': account['ACCOUNT_ID'], 'account_name': account['NAME'],
                        'date': day.isoformat(), 'timezone': config['TIMEZONE'], 'generated_at': multi.iso(end),
                        'complete': True, 'segments': {'expected': 48, 'present': 48}, 'errors': [],
                        'scope': multi.scope_for(config, account)})
    receipt = multi._delivery_path(config, day)
    already_sent = receipt.exists()
    smtp = Mock()
    smtp.ehlo.return_value = (250, b'ok')
    smtp.send_message.return_value = {}
    with patch('rds_mail.smtplib.SMTP_SSL', return_value=smtp) as constructor:
        status = multi.deliver(config, day, end, reports=reports)
    assert status['status'] == 'accepted'
    assert constructor.call_count == (0 if already_sent else 1), 'persisted receipt lost during restart'
    message_path = output / '.docker-smoke-message.eml'
    if not already_sent:
        message = smtp.send_message.call_args.args[0]
        message_path.write_bytes(message.as_bytes())
    message = BytesParser(policy=policy.default).parsebytes(message_path.read_bytes())
    plain = message.get_body(preferencelist=('plain',)).get_content()
    html = message.get_body(preferencelist=('html',)).get_content()
    for value in ('各位领导和同事好：', 'RDS 来源 IP 审计汇总', '账号总数：2',
                  '2026-11-05 10:00:00 至 2026-11-06 10:00:00', '192.0.2.22'):
        assert value in plain, value
    assert '<table' in html and '192.0.2.22' in html
    attachments = list(message.iter_attachments())
    assert len(attachments) == 2
    assert all(part.get_payload(decode=True).startswith(b'%PDF-') for part in attachments)
    assert 'FICTIONAL-AUTH' not in plain + html and 'UPDATE t' not in plain + html
    print('Production image: SQL parser, Chinese PDFs, HTML/text mail and persistent receipts verified offline.')


if __name__ == '__main__':
    main()
