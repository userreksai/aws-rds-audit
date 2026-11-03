"""IP-only scope is determined before SQL parsing; uncertain sources stay visible."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rds_summary import SummaryAccumulator, canonical_source_ip, merge_summaries, validate_summary
from test_rds_ip_summary import sql_event
from test_rds_report import START, END, management


class OnlyIpTests(unittest.TestCase):
    def collect(self, events=(), apis=(), dimension="ip"):
        with tempfile.TemporaryDirectory() as temporary:
            with SummaryAccumulator(temporary, START, END, dimension=dimension) as accumulator:
                results = [accumulator.process_audit(event) for event in events]
                results += [accumulator.process_management(event) for event in apis]
                payload = accumulator.finish()
                stored = json.loads((Path(temporary) / "operation-summary.json").read_text(encoding="utf-8"))
                self.assertEqual(stored, payload)
            self.assertEqual([item.name for item in Path(temporary).iterdir()], ["operation-summary.json"])
            return payload, results

    def test_non_ip_is_excluded_before_unclassified_or_malformed_sql_is_examined(self):
        events = []
        for index, source in enumerate(("", "localhost", "proxy.internal", "AWS Internal/42", "ec2.amazonaws.com")):
            event = sql_event(source=source, event_id=str(index), sql="CALL PRIVATE_VALUE()")
            # Header is intact but SQL quote and retcode are absent. Neither
            # payload validity nor classification matters outside IP scope.
            event["message"] = ",".join(event["message"].split(",", 8)[:8]) + ",'PRIVATE_UNCLOSED"
            events.append(event)
        with patch("rds_report.parse_audit_record", side_effect=AssertionError("out-of-scope SQL must not be parsed")):
            payload, results = self.collect(events + [events[0]])
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["actors"], [])
        self.assertEqual(payload["schema_version"], 3)
        self.assertEqual(payload["coverage"]["filtered_no_ip_records"], 5)
        self.assertEqual(payload["coverage"]["unparsed_records"], 0)
        self.assertTrue(all(result["unknown_records"] == 0 for result in results))
        self.assertNotIn("PRIVATE", json.dumps(payload))

    def test_ip_unknown_sql_and_malformed_sql_remain_incomplete(self):
        unknown = sql_event(source="192.0.2.1", sql="CALL secret_routine()", event_id="unknown")
        bad = sql_event(source="192.0.2.1", event_id="bad")
        bad["message"] = bad["message"].rsplit(",", 1)[0] + ",not-a-return-code"
        payload, results = self.collect([unknown, bad])
        self.assertFalse(payload["complete"])
        self.assertEqual(payload["actors"], [])
        self.assertEqual(payload["coverage"]["unknown_reasons"], {"parse_sql": 1, "unclassified_sql": 1})
        self.assertEqual(payload["coverage"]["source_unreadable_records"], 0)
        self.assertEqual([result["unknown_records"] for result in results], [1, 1])
        self.assertFalse(validate_summary(payload, START, END, dimension="ip")["complete"])

    def test_unreadable_header_is_not_guessed_to_have_no_ip(self):
        event = sql_event(source="", event_id="bad-prefix")
        event["message"] = "truncated,header,with,localhost"
        payload, _ = self.collect([event, event])
        self.assertFalse(payload["complete"])
        self.assertEqual(payload["coverage"]["filtered_no_ip_records"], 0)
        self.assertEqual(payload["coverage"]["source_unreadable_records"], 1)
        self.assertEqual(payload["coverage"]["unknown_reasons"], {"parse_sql": 1})

    def test_literal_ips_and_explicit_ports_are_normalized(self):
        sources = ["192.0.2.1", "192.0.2.1:0", "192.0.2.1:65535", "192.0.2.1:000443",
                   " 2001:0DB8:0:0:0:0:0:1 ", "2001:db8::1", "[2001:db8::1]:3306", "[2001:db8::1]",
                   "[::1]:0", "::1"]
        payload, _ = self.collect([sql_event(source=source, event_id=str(index)) for index, source in enumerate(sources)])
        rows = {row["source_ip"]: row for row in payload["actors"]}
        self.assertEqual({source: row["total"] for source, row in rows.items()},
                         {"192.0.2.1": 4, "2001:db8::1": 4, "::1": 2})
        self.assertTrue(all(row["actor_type"] == "来源 IP" for row in rows.values()))
        self.assertEqual(canonical_source_ip("2001:db8::1:3306"), "2001:db8::1:3306")

    def test_bad_addresses_and_ports_are_excluded_without_dns_lookup(self):
        invalid = ["localhost", "proxy.internal:3306", "256.0.0.1", "192.0.2.1:65536", "192.0.2.1:-1",
                   "192.0.2.1:port", "[2001:db8::1]:65536", "[192.0.2.1]:443", "[not-an-ip]:443",
                   "192.0.2.1:1:2", "192.0.2.1,192.0.2.2", "fe80::1%eth0", "AWS Internal/32"]
        for source in invalid:
            with self.subTest(source=source):
                self.assertIsNone(canonical_source_ip(source))
        payload, _ = self.collect([sql_event(source=source, event_id=str(index)) for index, source in enumerate(invalid) if "," not in source])
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["actors"], [])
        self.assertEqual(payload["coverage"]["filtered_no_ip_records"], len(invalid) - 1)

    def test_management_only_valid_ip_and_deduplicated_filtered_sources_survive(self):
        excluded = [management("m" + str(index), sourceIPAddress=source)
                    for index, source in enumerate(("", "AWS Internal/1", "rds.amazonaws.com", "localhost"))]
        included = [management("ip", sourceIPAddress="203.0.113.1:443"),
                    management("ip6", sourceIPAddress="[2001:db8::1]:65535")]
        payload, _ = self.collect(apis=excluded + included + [excluded[0], included[0]])
        self.assertTrue(payload["complete"])
        self.assertEqual({row["source_ip"] for row in payload["actors"]}, {"203.0.113.1", "2001:db8::1"})
        self.assertEqual(sum(row["total"] for row in payload["actors"]), 2)
        self.assertEqual(payload["coverage"]["filtered_no_ip_records"], 4)

    def test_known_auxiliary_rows_with_empty_retcode_are_out_of_statement_scope(self):
        operations = ("CONNECT", "DISCONNECT", "FAILED_CONNECT", "CHANGEUSER", "READ", "WRITE", "CREATE", "ALTER", "RENAME", "DROP")
        events = []
        for operation in operations:
            event = sql_event(operation=operation, sql="private_object", event_id=operation)
            event["message"] = event["message"].rsplit(",", 1)[0] + ","
            events.append(event)
        with patch("rds_report.parse_audit_record", side_effect=AssertionError("auxiliary payload is out of scope")):
            payload, results = self.collect(events)
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["actors"], [])
        self.assertEqual(payload["coverage"]["filtered_auxiliary"], len(operations))
        self.assertTrue(all(result["auxiliary_records"] == 1 for result in results))

    def test_query_empty_retcode_and_unrecognized_operation_remain_unknown(self):
        query = sql_event(event_id="query")
        query["message"] = query["message"].rsplit(",", 1)[0] + ","
        unknown = sql_event(operation="UNRECOGNIZED_OPERATION", event_id="unknown-op")
        payload, _ = self.collect([query, unknown])
        self.assertFalse(payload["complete"])
        self.assertEqual(payload["coverage"]["filtered_auxiliary"], 0)
        self.assertEqual(payload["coverage"]["unknown_reasons"], {"parse_sql": 2})

    def test_user_mode_schema_and_quality_behavior_are_unchanged(self):
        event = sql_event(source="localhost", sql="CALL original_unknown()")
        payload, _ = self.collect([event], dimension="user")
        self.assertEqual(payload["schema_version"], 1)
        self.assertNotIn("dimension", payload)
        self.assertNotIn("filtered_no_ip_records", payload["coverage"])
        self.assertNotIn("source_unreadable_records", payload["coverage"])
        self.assertFalse(payload["complete"])
        self.assertEqual(payload["coverage"]["unknown_reasons"], {"unclassified_sql": 1})
        valid, _ = self.collect([sql_event(source="localhost")], dimension="user")
        self.assertEqual(valid["actors"][0]["total"], 1)

    def test_merge_rejects_old_v2_and_non_ip_actors_and_validates_new_counters(self):
        payload, _ = self.collect([sql_event()])
        old = deepcopy(payload)
        old["schema_version"] = 2
        with self.assertRaisesRegex(ValueError, "format"):
            validate_summary(old, START, END, dimension="ip")
        for field in ("filtered_no_ip_records", "source_unreadable_records"):
            for value in (-1, True, "1"):
                invalid = deepcopy(payload)
                invalid["coverage"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_summary(invalid, START, END, dimension="ip")
        for source in ("localhost", "", "AWS Internal/1"):
            invalid = deepcopy(payload)
            invalid["actors"][0]["source_ip"] = source
            with self.subTest(source=source), self.assertRaises(ValueError):
                validate_summary(invalid, START, END, dimension="ip")
        optional = deepcopy(payload)
        optional["coverage"].pop("filtered_no_ip_records")
        optional["coverage"].pop("source_unreadable_records")
        merged = merge_summaries([optional], START, END, dimension="ip")
        self.assertEqual(merged["coverage"]["filtered_no_ip_records"], 0)
        self.assertEqual(merged["coverage"]["source_unreadable_records"], 0)
        self.assertEqual(merged["schema_version"], 3)


if __name__ == "__main__":
    unittest.main()
