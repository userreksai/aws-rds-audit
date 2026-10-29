"""Keep classified mutations at collection time; never call AWS."""
import copy
from datetime import datetime, timezone
import unittest

from rds_change_filter import audit_event_decision, keep_management_event
from rds_report import classify_sql


def event(sql="UPDATE t SET x=1", *, operation="QUERY", code=0):
    stamp = datetime(2026, 10, 29, 1, tzinfo=timezone.utc).timestamp()
    return {"region": "ap-east-1", "logGroupName": "/aws/rds/cluster/shenji/audit", "logStreamName": "db", "eventId": "cw-1", "timestamp": int(stamp * 1000), "message": f"{int(stamp * 1000000)},db,user,203.0.113.1,1,1,{operation},shop,'{sql}',{code}"}


class CollectionFilterTests(unittest.TestCase):
    def test_read_only_management_is_removed_but_failed_mutation_is_kept(self):
        self.assertFalse(keep_management_event({"eventName": "DescribeDBInstances", "readOnly": True}))
        self.assertFalse(keep_management_event({"eventName": "CreateDBInstance", "readOnly": "true"}))
        self.assertTrue(keep_management_event({"eventName": "DeleteDBInstance", "readOnly": False, "errorCode": "AccessDenied"}))

    def test_select_and_auxiliary_events_do_not_enter_main_data(self):
        for sql in ("SELECT 1", "select * from t", "/* note */ SHOW TABLES", "-- note\nDESC t", "EXPLAIN UPDATE t SET x=1"):
            with self.subTest(sql=sql):
                decision = audit_event_decision(event(sql))
                self.assertFalse(decision["keep"])
                self.assertEqual(decision["read_records"], 1)
                self.assertEqual(decision["unknown_records"], [])
        for operation in ("CONNECT", "DISCONNECT", "WRITE", "READ", "CREATE", "ALTER"):
            with self.subTest(operation=operation):
                decision = audit_event_decision(event("table_name", operation=operation))
                self.assertFalse(decision["keep"])
                self.assertEqual(decision["auxiliary_records"], 1)

    def test_insert_select_and_failed_ddl_are_preserved(self):
        for sql, code in (("INSERT INTO target SELECT * FROM source", 0), ("CREATE TABLE target AS SELECT * FROM source", 0), ("DROP TABLE t", 1142), ("/* hint */ update t set x=2", 0)):
            with self.subTest(sql=sql):
                decision = audit_event_decision(event(sql, code=code))
                self.assertTrue(decision["keep"])
                self.assertEqual(decision["change_records"], 1)
                self.assertEqual(decision["read_records"], 0)

    def test_mixed_multi_record_envelope_keeps_original_message_and_record_indexes(self):
        value = event("SELECT 1")
        value["message"] += "\n" + event("INSERT INTO t VALUES(1)")["message"]
        value["message"] += "\n" + event("CALL change_balance(1)")["message"]
        original = copy.deepcopy(value)
        decision = audit_event_decision(value)
        self.assertTrue(decision["keep"])
        self.assertEqual(decision["change_records"], 1)
        self.assertEqual(decision["read_records"], 1)
        self.assertEqual(len(decision["retained_segments"]), 1)
        self.assertEqual(decision["retained_segments"][0]["record_index"], 1)
        self.assertIn("INSERT INTO", decision["retained_segments"][0]["raw"])
        self.assertNotIn("SELECT 1", decision["retained_segments"][0]["raw"])
        self.assertEqual(decision["unknown_records"][0]["record_index"], 2)
        self.assertEqual(decision["unknown_records"][0]["eventId"], "cw-1")
        self.assertEqual(value, original)

    def test_a_previously_filtered_message_keeps_original_indexes(self):
        value = event("DELETE FROM t")
        value["original_record_indexes"] = [9]
        result = audit_event_decision(value)
        self.assertEqual(result["retained_segments"], [{"raw": value["message"], "record_index": 9}])
        value["original_record_indexes"] = [True]
        result = audit_event_decision(value)
        self.assertFalse(result["keep"])
        self.assertEqual(result["parse_errors"], 1)

    def test_unknown_and_truncated_records_are_not_misreported_as_queries(self):
        for sql in ("CALL f()", "EXECUTE prepared_stmt", "WITH x AS (SELECT 1) UPDATE t SET x=2", "SELECT 1; DELETE FROM t", "EXPLAIN ANALYZE UPDATE t SET x=1"):
            with self.subTest(sql=sql):
                decision = audit_event_decision(event(sql))
                self.assertFalse(decision["keep"])
                self.assertEqual(decision["read_records"], 0)
                self.assertEqual(decision["unknown_records"][0]["reason"], "unclassified_sql")
        malformed = event()
        malformed["message"] = malformed["message"][:-3]
        decision = audit_event_decision(malformed)
        self.assertFalse(decision["keep"])
        self.assertEqual(decision["parse_errors"], 1)
        self.assertEqual(decision["unknown_records"][0]["reason"], "parse_error")
        self.assertEqual(decision["unknown_records"][0]["raw"], malformed["message"])

    def test_explicit_replace_and_load_writes_are_classified(self):
        self.assertEqual(classify_sql("REPLACE INTO t VALUES(1)"), "修改")
        self.assertEqual(classify_sql("LOAD DATA INFILE 'data.csv' INTO TABLE t"), "新增")
        self.assertEqual(classify_sql("SET GLOBAL max_connections=200"), "修改")


if __name__ == "__main__":
    unittest.main()
