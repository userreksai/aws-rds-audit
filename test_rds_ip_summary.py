"""Source-IP summaries keep SQL and management requests separate and private."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest

from rds_summary import SummaryAccumulator, merge_summaries, validate_summary
from test_rds_report import START, END, WHEN, audit_event, management


def sql_event(source="192.0.2.22", user="writer", **kwargs):
    event = audit_event(**kwargs)
    fields = event["message"].split(",", 8)
    fields[2:4] = [user, source]
    event["message"] = ",".join(fields)
    return event


class IpSummaryTests(unittest.TestCase):
    def summarize(self, events=(), management_events=(), start=START, end=END):
        with tempfile.TemporaryDirectory() as temporary:
            with SummaryAccumulator(temporary, start, end, dimension="ip") as accumulator:
                for event in events:
                    accumulator.process_audit(event)
                for event in management_events:
                    accumulator.process_management(event)
                payload = accumulator.finish()
                self.assertEqual(list(Path(temporary).glob("*.json")), [Path(temporary) / "operation-summary.json"])
                self.assertEqual(json.loads((Path(temporary) / "operation-summary.json").read_text(encoding="utf-8")), payload)
            self.assertFalse(list(Path(temporary).glob("*.sqlite3")))
            return payload

    def test_sql_users_merge_by_ip_and_failed_requests_are_separate(self):
        payload = self.summarize([
            sql_event(user="app1", sql="INSERT INTO private_table VALUES ('DO_NOT_RETAIN')", event_id="one"),
            sql_event(user="app2", sql="UPDATE private_table SET a=2", event_id="two"),
            sql_event(user="app3", sql="DELETE FROM private_table", event_id="three", code=1142),
            sql_event(source="192.0.2.23", sql="DELETE FROM private_table", event_id="four"),
        ])
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["dimension"], "ip")
        self.assertEqual(len(payload["actors"]), 2)
        row = payload["actors"][0]
        self.assertEqual(row["actor"], "192.0.2.22")
        self.assertEqual(row["source_ip"], "192.0.2.22")
        self.assertEqual(row["actor_type"], "来源 IP")
        self.assertEqual(row["total"], 3)
        self.assertEqual(row["failed"], 1)
        self.assertEqual(row["counts"], {"新增": 1, "删除": 0, "修改": 1, "其他操作": 0})
        self.assertEqual(row["attempted_counts"]["删除"], 1)
        text = json.dumps(payload, ensure_ascii=False)
        for secret in ("private_table", "DO_NOT_RETAIN", "app1", "connection_id", "UPDATE"):
            self.assertNotIn(secret, text)

    def test_management_users_merge_by_ip_but_do_not_merge_with_sql(self):
        events = [
            management("m1", "CreateDBInstance", sourceIPAddress="192.0.2.22"),
            management("m2", "ModifyDBInstance", sourceIPAddress="192.0.2.22",
                       userIdentity={"type": "IAMUser", "userName": "other-user", "arn": "arn:aws:iam::123456789012:user/other-user"}),
            management("m3", "DeleteDBInstance", sourceIPAddress="192.0.2.22", errorCode="AccessDenied"),
        ]
        payload = self.summarize([sql_event()], events + [events[0]])
        self.assertEqual(len(payload["actors"]), 2)
        rows = {row["source_kind"]: row for row in payload["actors"]}
        self.assertEqual(rows["management"]["total"], 3)
        self.assertEqual(rows["management"]["failed"], 1)
        self.assertEqual(rows["management"]["counts"]["新增"], 1)
        self.assertEqual(rows["management"]["counts"]["修改"], 1)
        self.assertEqual(rows["sql"]["total"], 1)
        self.assertNotEqual(rows["sql"]["actor_key"], rows["management"]["actor_key"])

    def test_ipv6_is_canonical_and_surrounding_whitespace_is_removed(self):
        payload = self.summarize([
            sql_event(source=" 2001:0DB8:0000:0000:0000:0000:0000:0001 ", event_id="one"),
            sql_event(source="2001:db8::1", event_id="two"),
            sql_event(source=" 192.0.2.22 ", event_id="three"),
        ])
        self.assertEqual([(row["source_ip"], row["total"]) for row in payload["actors"]],
                         [("2001:db8::1", 2), ("192.0.2.22", 1)])

    def test_hostname_and_unknown_source_are_marked_without_inventing_ip(self):
        payload = self.summarize([
            sql_event(source="proxy.internal", event_id="host"),
            sql_event(source="", event_id="empty"),
            sql_event(source="未知来源", event_id="literal-host"),
        ])
        self.assertEqual(len(payload["actors"]), 3)
        rows = {row["source_ip"]: row for row in payload["actors"]}
        self.assertEqual(rows["proxy.internal"]["actor_type"], "来源主机")
        self.assertEqual(rows[""]["actor"], "未知来源")
        self.assertEqual(rows[""]["actor_type"], "未知来源")
        self.assertNotEqual(rows[""]["actor_key"], rows["未知来源"]["actor_key"])

    def test_duplicate_multirecord_event_is_counted_once_per_record(self):
        first = sql_event(event_id="batch", sql="INSERT INTO t VALUES(1)")
        first["message"] += "\n" + sql_event(sql="DELETE FROM t")["message"]
        payload = self.summarize([first, first])
        self.assertEqual(payload["actors"][0]["total"], 2)
        self.assertEqual(payload["actors"][0]["counts"]["新增"], 1)
        self.assertEqual(payload["actors"][0]["counts"]["删除"], 1)
        self.assertEqual(payload["coverage"]["duplicate_cloudwatch_events"], 1)

    def test_queries_and_auxiliary_table_records_do_not_inflate_changes(self):
        payload = self.summarize([
            sql_event(sql="SELECT * FROM t", event_id="read"),
            sql_event(sql="t", operation="WRITE", event_id="table"),
            sql_event(event_id="update"),
        ])
        self.assertEqual(payload["actors"][0]["total"], 1)
        self.assertEqual(payload["coverage"]["filtered_queries"], 1)
        self.assertEqual(payload["coverage"]["filtered_auxiliary"], 1)

    def test_merge_normalizes_ip_and_detects_gaps_and_overlaps(self):
        middle = START + timedelta(hours=2)
        first = self.summarize([sql_event(source="2001:0db8::1", when=START)], start=START, end=middle)
        second = self.summarize([sql_event(source="2001:db8::1", when=middle)], start=middle, end=END)
        merged = merge_summaries([second, first], START, END, dimension="ip")
        self.assertTrue(merged["complete"])
        self.assertEqual(merged["actors"][0]["total"], 2)
        self.assertEqual(merged["dimension"], "ip")
        self.assertTrue(validate_summary(merged, START, END, dimension="ip")["complete"])
        self.assertFalse(merge_summaries([first], START, END, dimension="ip")["complete"])
        with self.assertRaisesRegex(ValueError, "overlap"):
            merge_summaries([first, first], START, END, dimension="ip")

    def test_no_segments_is_incomplete_and_unknown_parsing_remains_incomplete(self):
        self.assertFalse(merge_summaries([], START, END, dimension="ip")["complete"])
        payload = self.summarize([sql_event(sql="CALL mystery()")])
        self.assertFalse(payload["complete"])
        self.assertFalse(validate_summary(payload, START, END, dimension="ip")["complete"])
        self.assertEqual(payload["actors"], [])
        self.assertEqual(payload["coverage"]["unknown_reasons"], {"unclassified_sql": 1})

    def test_modes_cannot_be_mixed_or_inferred_from_legacy_user_summaries(self):
        ip_payload = self.summarize([sql_event()])
        with tempfile.TemporaryDirectory() as temporary:
            with SummaryAccumulator(temporary, START, END) as accumulator:
                accumulator.process_audit(sql_event())
                user_payload = accumulator.finish()
        self.assertEqual(user_payload["schema_version"], 1)
        self.assertNotIn("dimension", user_payload)
        self.assertNotIn("source_ip", user_payload["actors"][0])
        self.assertTrue(validate_summary(user_payload, START, END)["complete"])
        for payload, dimension in ((user_payload, "ip"), (ip_payload, "user")):
            with self.subTest(dimension=dimension):
                with self.assertRaisesRegex(ValueError, "format"):
                    validate_summary(payload, START, END, dimension=dimension)
        for dimension in ("ip", "user"):
            with self.assertRaisesRegex(ValueError, "format"):
                merge_summaries([ip_payload, user_payload], START, END, dimension=dimension)

    def test_ip_mode_rejects_invalid_metadata_sources_and_counters(self):
        payload = self.summarize([sql_event()])
        for mutate in (
            lambda data: data.pop("dimension"),
            lambda data: data.update(dimension="user"),
            lambda data: data.update(schema_version=True),
            lambda data: data["actors"][0].pop("source_ip"),
            lambda data: data["actors"][0].update(source_ip=123),
            lambda data: data["actors"][0].update(total=-1),
        ):
            invalid = deepcopy(payload)
            mutate(invalid)
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validate_summary(invalid, START, END, dimension="ip")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "dimension"):
                SummaryAccumulator(temporary, START, END, dimension="other")


if __name__ == "__main__":
    unittest.main()
