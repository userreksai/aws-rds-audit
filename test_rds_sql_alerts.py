"""SQL alert checkpoints and transports are local/fake; no AWS or Lark calls."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from rds_cache import CacheStore
from rds_sql_alerts import SqlChangeAlerts, DEFAULT_COMMANDS, MAX_PAYLOAD_BYTES

UTC = timezone.utc
NOW = datetime(2026, 10, 29, 9, 5, tzinfo=UTC)
START = NOW.replace(hour=8, minute=30)
END = START + timedelta(minutes=30)
ACCOUNT = "123456789012"
SCOPE = {"profile": "audit", "regions": "ap-east-1", "interval_minutes": 30, "filter_version": "changes-v1"}


def iso(value):
    return value.isoformat().replace("+00:00", "Z")


def event(sql="UPDATE t SET x=1", *, identifier="one", stream="writer", when=None, code=0, actor="admin", operation="QUERY"):
    when = when or START + timedelta(minutes=1)
    return {"eventId": identifier, "region": "ap-east-1", "logGroupName": "/aws/rds/cluster/example/audit", "logStreamName": stream,
            "timestamp": int(when.timestamp()*1000),
            "message": f"{int(when.timestamp()*1000000)},server,{actor},203.0.113.1,1,1,{operation},example,'{sql}',{code}"}


class SqlChangeAlertTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = CacheStore(Path(self.temporary.name)/"cache", ACCOUNT, SCOPE)
        self.alerts = SqlChangeAlerts(self.store, NOW)

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def snapshot(self, events, *, start=START, end=END, account=ACCOUNT, partial=False):
        directory = self.store.directory / "segments" / ("attempt-"+uuid4().hex)
        (directory/"cloudwatch").mkdir(parents=True)
        source = {"identity": {"Account": account}, "window": {"start_inclusive": iso(start), "end_exclusive": iso(end)},
                  "collection_status": "partial" if partial else "ok", "checks": [{"status":"error","error_type":"AccessDenied"}] if partial else []}
        (directory/"report.json").write_text(json.dumps(source),encoding="utf-8")
        (directory/"cloudwatch/events.jsonl").write_text("".join(json.dumps(item,ensure_ascii=False)+"\n" for item in events),encoding="utf-8")
        return directory

    def test_latest_changes_include_failed_attempts_but_exclude_backfill_reads_and_unknown(self):
        past = self.snapshot([event("DELETE FROM t", when=START-timedelta(hours=1))], start=START-timedelta(hours=1),end=END-timedelta(hours=1))
        self.assertEqual(self.alerts.scan_snapshot(START-timedelta(hours=1),END-timedelta(hours=1),past,NOW),0)
        statements = ["DELETE FROM t", "UPDATE t SET x=1", "DROP TABLE t", "TRUNCATE TABLE t", "ALTER TABLE t ADD x INT", "SELECT * FROM t", "INSERT INTO t VALUES (1)", "WITH ids AS (SELECT 1) DELETE FROM t"]
        rows = [event(sql,identifier=str(index)) for index,sql in enumerate(statements)]
        rows += [event("UPDATE t SET x=2",identifier="failed",code=1142),event("t",identifier="table",operation="WRITE")]
        path = self.snapshot(rows,partial=True)
        self.assertEqual(self.alerts.scan_snapshot(START,END,path,NOW),6)
        delivered = []
        self.assertEqual(self.alerts.flush(delivered.append,NOW)["pending_events"],0)
        text = delivered[0]["message"]
        self.assertIn("账号：admin",text)
        self.assertIn("失败：返回码 1142",text)
        self.assertIn("2026-10-29 16:31:00",text)
        self.assertNotIn("SELECT",text)
        self.assertNotIn("INSERT",text)
        self.assertIn("ALTER TABLE",text)

    def test_dedup_uses_stream_and_original_record_index_not_sql_text(self):
        first,second=event(),event(identifier="two")
        mixed={**event(identifier="mixed"),"message":first["message"]+"\n"+second["message"],"original_record_indexes":[3,7]}
        other={**mixed,"logStreamName":"reader"}
        path=self.snapshot([mixed,mixed,other])
        self.assertEqual(self.alerts.scan_snapshot(START,END,path,NOW),4)
        self.assertEqual(self.alerts.scan_snapshot(START,END,path,NOW),0)
        delivered=[]
        self.alerts.flush(delivered.append,NOW)
        self.assertEqual(delivered[0]["operation_count"],4)

    def test_cutoff_persists_across_restarts_and_future_operation_is_not_alerted(self):
        original=self.alerts.cutoff
        self.store.close()
        self.store=CacheStore(Path(self.temporary.name)/"cache",ACCOUNT,SCOPE)
        self.alerts=SqlChangeAlerts(self.store,NOW+timedelta(hours=3))
        self.assertEqual(self.alerts.cutoff,original)
        path=self.snapshot([event(when=START-timedelta(seconds=1)),event(identifier="future",when=NOW+timedelta(hours=1))])
        self.assertEqual(self.alerts.scan_snapshot(START,END,path,NOW),0)

    def test_foreign_identity_and_mismatched_window_are_rejected_without_enqueue(self):
        foreign=self.snapshot([event()],account="999999999999")
        with self.assertRaisesRegex(ValueError,"another AWS account"):
            self.alerts.scan_snapshot(START,END,foreign,NOW)
        wrong=self.snapshot([event()],end=END+timedelta(minutes=30))
        with self.assertRaisesRegex(ValueError,"segment window"):
            self.alerts.scan_snapshot(START,END,wrong,NOW)
        self.assertEqual(self.alerts.stats()["pending_events"],0)

    def test_partial_collector_snapshot_can_alert_known_changes(self):
        path=self.snapshot([event("DELETE FROM t")],partial=True)
        self.assertEqual(self.alerts.scan_snapshot(START,END,path,NOW),1)
        delivered=[]
        self.alerts.flush(delivered.append,NOW)
        self.assertEqual(len(delivered),1)

    def test_failed_delivery_retains_fixed_batch_id_members_and_recovers_after_restart(self):
        path=self.snapshot([event(identifier="initial")])
        self.alerts.scan_snapshot(START,END,path,NOW)
        attempted=[]
        def fail(payload):
            attempted.append(payload)
            raise OSError("private transport failure")
        self.assertEqual(self.alerts.flush(fail,NOW,max_messages=1)["failed_messages"],1)
        later=self.snapshot([event(identifier="new")])
        self.alerts.scan_snapshot(START,END,later,NOW+timedelta(seconds=1))
        self.store.close()
        self.store=CacheStore(Path(self.temporary.name)/"cache",ACCOUNT,SCOPE)
        self.alerts=SqlChangeAlerts(self.store,NOW+timedelta(minutes=2))
        delivered=[]
        result=self.alerts.flush(delivered.append,NOW+timedelta(minutes=2),max_messages=2)
        self.assertEqual(result["sent_messages"],2)
        self.assertEqual(delivered[0],attempted[0])
        self.assertNotEqual(delivered[0]["event_id"],delivered[1]["event_id"])
        self.assertEqual(result["pending_events"],0)

    def test_large_volume_is_batched_bounded_redacted_and_retained_past_round_limit(self):
        sql="UPDATE t SET password='PRIVATE-CREDENTIAL'"
        rows=[event(sql,identifier="secret",actor="<at user_id=all>everyone</at>")]
        rows += [event("UPDATE t SET x='"+"中"*800+"'",identifier=str(index)) for index in range(31)]
        path=self.snapshot(rows)
        self.assertEqual(self.alerts.scan_snapshot(START,END,path,NOW),32)
        delivered=[]
        first=self.alerts.flush(delivered.append,NOW,max_messages=1)
        self.assertGreater(first["pending_events"],0)
        self.assertEqual(first["sent_messages"],1)
        self.alerts.flush(delivered.append,NOW,max_messages=20)
        self.assertEqual(self.alerts.stats()["pending_events"],0)
        self.assertEqual(sum(item["operation_count"] for item in delivered),32)
        for payload in delivered:
            self.assertLessEqual(payload["operation_count"],10)
            self.assertLessEqual(len(json.dumps(payload,ensure_ascii=False,separators=(",", ":")).encode()),MAX_PAYLOAD_BYTES)
        combined=json.dumps(delivered,ensure_ascii=False)
        self.assertNotIn("PRIVATE-CREDENTIAL",combined)
        self.assertNotIn("<at",combined)

    def test_committed_scan_compensates_once_and_only_rescans_changed_digest(self):
        path=self.snapshot([event()])
        relative=str(path.relative_to(self.store.directory))
        self.store.connection.execute("INSERT INTO buckets(start,end,status,active_path,active_digest) VALUES(?,?,'succeeded',?,?)",(int(START.timestamp()),int(END.timestamp()),relative,"one"))
        self.store.connection.commit()
        self.assertEqual(self.alerts.scan_committed(NOW),1)
        with patch.object(self.alerts,"scan_snapshot",side_effect=AssertionError("unchanged snapshots must not reread SQL")):
            self.assertEqual(self.alerts.scan_committed(NOW),0)
        self.store.connection.execute("UPDATE buckets SET active_digest='two'")
        self.store.connection.commit()
        self.assertEqual(self.alerts.scan_committed(NOW),0)

    def test_notification_rejection_retries_with_backoff(self):
        path=self.snapshot([event()])
        self.alerts.scan_snapshot(START,END,path,NOW)
        rejected=Mock(return_value={"code":19022})
        self.assertEqual(self.alerts.flush(rejected,NOW)["failed_messages"],1)
        self.assertEqual(self.alerts.flush(rejected,NOW+timedelta(seconds=30))["failed_messages"],0)
        self.assertEqual(rejected.call_count,1)
        delivered=[]
        self.alerts.flush(delivered.append,NOW+timedelta(seconds=61))
        self.assertEqual(len(delivered),1)

    def test_same_round_commit_does_not_reread_attempt_already_scanned(self):
        path=self.snapshot([event()])
        self.assertEqual(self.alerts.scan_snapshot(START,END,path,NOW),1)
        self.store.connection.execute("INSERT INTO buckets(start,end,status,active_path,active_digest) VALUES(?,?,'succeeded',?,?)",(int(START.timestamp()),int(END.timestamp()),str(path.relative_to(self.store.directory)),"one"))
        self.store.connection.commit()
        with patch.object(self.alerts,"scan_snapshot",side_effect=AssertionError("same round should reuse its completed scan")):
            self.assertEqual(self.alerts.scan_committed(NOW),0)


if __name__ == "__main__":
    unittest.main()
