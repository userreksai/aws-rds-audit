"""Summary privacy, exact deduplication, boundaries and compact storage."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest

from rds_summary import SummaryAccumulator, merge_summaries, summarize_directory, validate_summary
from test_rds_report import START, END, WHEN, audit_event, management


class SummaryTests(unittest.TestCase):
    def test_only_user_totals_survive_and_temporary_identities_are_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with SummaryAccumulator(directory, START, END) as accumulator:
                temporary_path = accumulator.path
                accumulator.process_management(management())
                accumulator.process_audit(audit_event("UPDATE sensitive_table SET secret='DO_NOT_STORE'"))
                accumulator.process_audit(audit_event("DELETE FROM sensitive_table", event_id="failed", code=1142))
                accumulator.process_audit(audit_event("CALL unknown_secret('DO_NOT_STORE')", event_id="unknown"))
                payload = accumulator.finish()
                self.assertTrue(temporary_path.exists())
                self.assertEqual(len(payload["actors"]), 2)
                sql_actor = next(actor for actor in payload["actors"] if actor["source_kind"] == "sql")
                self.assertEqual(sql_actor["counts"]["修改"], 1)
                self.assertEqual(sql_actor["attempted_counts"]["删除"], 1)
                self.assertEqual(sql_actor["failed"], 1)
                self.assertFalse(payload["complete"])
                self.assertEqual(payload["coverage"]["unknown_reasons"], {"unclassified_sql": 1})
            self.assertFalse(temporary_path.exists())
            self.assertEqual([path.name for path in directory.iterdir()], ["operation-summary.json"])
            text = (directory / "operation-summary.json").read_text(encoding="utf-8")
            for forbidden in ("DO_NOT_STORE", "sensitive_table", "UPDATE", "DELETE FROM", "CALL", "source_ip", "connection_id"):
                self.assertNotIn(forbidden, text)

    def test_record_identity_deduplicates_without_merging_distinct_streams_or_indexes(self):
        first = audit_event("INSERT INTO t VALUES(1)")
        second = audit_event("UPDATE t SET x=2")
        first["message"] += "\n" + second["message"]
        first["original_record_indexes"] = [2, 7]
        subset = {**first, "message": second["message"], "original_record_indexes": [7]}
        with tempfile.TemporaryDirectory() as temporary:
            with SummaryAccumulator(temporary, START, END) as accumulator:
                accumulator.process_audit(first)
                accumulator.process_audit(subset)
                accumulator.process_audit({**subset, "logStreamName": "other-stream"})
                payload = accumulator.finish()
        self.assertEqual(payload["actors"][0]["total"], 3)
        self.assertEqual(payload["actors"][0]["counts"]["新增"], 1)
        self.assertEqual(payload["actors"][0]["counts"]["修改"], 2)

    def test_missing_identity_is_unresolved_and_never_counted_as_complete(self):
        event = audit_event()
        event.pop("eventId")
        with tempfile.TemporaryDirectory() as temporary:
            with SummaryAccumulator(temporary, START, END) as accumulator:
                self.assertEqual(accumulator.process_audit(event)["unknown_records"], 1)
                payload = accumulator.finish()
        self.assertFalse(payload["complete"])
        self.assertEqual(payload["actors"], [])
        self.assertEqual(payload["coverage"]["unknown_reasons"], {"missing_event_id": 1})

    def test_cloudwatch_envelope_time_owns_all_records_across_internal_time_boundary(self):
        boundary = START + timedelta(minutes=30)
        before = audit_event("INSERT INTO t VALUES(1)", when=boundary-timedelta(seconds=1))
        after = audit_event("DELETE FROM t", when=boundary+timedelta(seconds=1))
        before["message"] += "\n" + after["message"]
        before["timestamp"] = int((boundary+timedelta(seconds=2)).timestamp()*1000)
        with tempfile.TemporaryDirectory() as temporary:
            with SummaryAccumulator(Path(temporary)/"first", START, boundary) as accumulator:
                accumulator.process_audit(before)
                first = accumulator.finish()
            with SummaryAccumulator(Path(temporary)/"second", boundary, END) as accumulator:
                accumulator.process_audit(before)
                second = accumulator.finish()
        self.assertEqual(first["actors"], [])
        self.assertEqual(second["actors"][0]["total"], 2)
        self.assertEqual(second["actors"][0]["counts"]["新增"], 1)
        self.assertEqual(second["actors"][0]["counts"]["删除"], 1)

    def test_merging_disjoint_segments_rejects_overlap_and_detects_gaps(self):
        middle = START + timedelta(hours=1)
        with tempfile.TemporaryDirectory() as temporary:
            with SummaryAccumulator(Path(temporary)/"first", START, middle) as accumulator:
                accumulator.process_audit(audit_event(when=START))
                first = accumulator.finish()
            with SummaryAccumulator(Path(temporary)/"second", middle, END) as accumulator:
                accumulator.process_audit(audit_event(event_id="second", when=middle))
                second = accumulator.finish()
        merged = merge_summaries([second, first], START, END)
        self.assertTrue(merged["complete"])
        self.assertEqual(merged["actors"][0]["total"], 2)
        self.assertFalse(merge_summaries([second], START, END)["complete"])
        with self.assertRaisesRegex(ValueError, "overlap"):
            merge_summaries([first, first], START, END)

    def test_validation_rejects_corrupt_counts_window_and_quality(self):
        with tempfile.TemporaryDirectory() as temporary:
            with SummaryAccumulator(temporary, START, END) as accumulator:
                accumulator.process_audit(audit_event())
                payload = accumulator.finish()
        self.assertTrue(validate_summary(payload, START, END)["complete"])
        for mutate in (
            lambda data: data["actors"][0].update(total=-1),
            lambda data: data["actors"][0]["counts"].update({"修改": True}),
            lambda data: data["actors"][0].update(total=9000000),
            lambda data: data["coverage"].update(unparsed_records=1),
            lambda data: data.update(schema_version=True),
        ):
            invalid = deepcopy(payload)
            mutate(invalid)
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validate_summary(invalid, START, END)
        with self.assertRaisesRegex(ValueError, "window"):
            validate_summary(payload, START+timedelta(minutes=1), END)

    def test_legacy_conversion_preserves_source_files_and_deduplicates_quarantine(self):
        event = audit_event("CALL mystery()")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory/"cloudwatch").mkdir()
            (directory/"quarantine").mkdir()
            (directory/"management-events.jsonl").write_text("", encoding="utf-8")
            source = directory/"cloudwatch/audit.jsonl"
            source.write_text(json.dumps(event)+"\n", encoding="utf-8")
            evidence = {**event, "record_index": 0, "reason": "unclassified_sql", "raw": "CALL mystery()"}
            (directory/"quarantine/sql-unclassified.jsonl").write_text(json.dumps(evidence)+"\n", encoding="utf-8")
            before = {path.relative_to(directory):path.read_bytes() for path in directory.rglob("*") if path.is_file()}
            payload = summarize_directory(directory, START, END)
            after = {path.relative_to(directory):path.read_bytes() for path in directory.rglob("*") if path.is_file()}
            self.assertEqual(before, after)
            self.assertEqual(payload["coverage"]["unclassified"], 1)
            self.assertEqual(payload["coverage"]["unparsed_records"], 1)

    def test_fixed_user_volume_keeps_summary_small_as_event_count_grows(self):
        with tempfile.TemporaryDirectory() as temporary:
            with SummaryAccumulator(temporary, START, END) as accumulator:
                for index in range(10000):
                    accumulator.process_audit(audit_event(event_id=str(index)))
                payload = accumulator.finish()
                self.assertEqual(payload["actors"][0]["total"], 10000)
                self.assertLess((Path(temporary)/"operation-summary.json").stat().st_size, 3000)


if __name__ == "__main__":
    unittest.main()
