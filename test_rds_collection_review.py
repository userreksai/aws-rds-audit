"""Large-volume regressions without AWS calls, sleeps or large allocations."""
from contextlib import redirect_stdout
from datetime import timedelta
from io import StringIO
import unittest
from unittest.mock import patch
import weakref

import rds_multi as multi
from rds_summary import merge_summaries
from test_rds_multi import DAY, MIDNIGHT, MultiFixture


class _TrackedSummary(dict):
    """A weak-referenceable summary so tests can observe retained bucket data."""


class CollectionReviewTests(MultiFixture):
    def test_report_merges_buckets_without_retaining_every_segment_payload(self):
        references, peak = [], 0

        def load(path, config, account, start, end):
            nonlocal peak
            summary = _TrackedSummary(merge_summaries([], start, end, dimension="ip"))
            summary["complete"] = True
            references.append(weakref.ref(summary))
            peak = max(peak, sum(reference() is not None for reference in references))
            return {"active": {"summary": summary, "complete": True}, "last_errors": []}

        with patch.object(multi, "load_bucket", side_effect=load):
            report = multi.build_report(self.config, self.account, DAY, MIDNIGHT + timedelta(days=1, hours=1))
        self.assertEqual(report["segments"], {"expected": 48, "present": 48})
        self.assertTrue(report["complete"])
        # One incoming segment plus the current generator/local references is
        # sufficient. Holding 48 summaries multiplies large-IP memory by 48.
        self.assertLessEqual(peak, 3, f"All {peak} cached segment payloads were retained until the final merge")

    def test_retry_delay_starts_after_a_slow_failed_attempt_finishes(self):
        self.seed_start()
        self.config["MAX_BUCKETS_PER_ACCOUNT_PER_RUN"] = 1
        started = MIDNIGHT + timedelta(minutes=35)
        completed = started + timedelta(minutes=10)
        elapsed = [0]

        def slow_failure(config, account, session, identity, start, end, directory):
            elapsed[0] += 600
            raise RuntimeError("simulated ten-minute failure")

        with redirect_stdout(StringIO()):
            result = multi.collect_account(self.config, self.account, started,
                                           session_factory=self.session, collector=slow_failure,
                                           monotonic=lambda: elapsed[0])
        self.assertEqual((result["processed"], result["failed"]), (1, 1))
        state = multi.read_json(multi.bucket_path(self.config, self.account, MIDNIGHT))
        self.assertGreaterEqual(state["next_retry"], int((completed + timedelta(minutes=5)).timestamp()),
                                "Retry deadline expired during the failed collection instead of following its completion")

    def test_six_slow_old_failures_allow_newer_segments_to_progress(self):
        self.seed_start()
        self.config["MAX_BUCKETS_PER_ACCOUNT_PER_RUN"] = 6
        failed_until = MIDNIGHT + timedelta(hours=3)
        clock = {"now": MIDNIGHT + timedelta(hours=4, minutes=5)}
        collected, fresh = [], []

        def slow_collection(config, account, session, identity, start, end, directory):
            collected.append(start)
            clock["now"] += timedelta(minutes=10)
            if start < failed_until:
                raise RuntimeError("simulated slow failure in one of the oldest six buckets")
            fresh.append(start)
            return self.snapshot(start, end)

        with redirect_stdout(StringIO()):
            for _ in range(4):
                multi.collect_account(self.config, self.account, clock["now"],
                                      session_factory=self.session, collector=slow_collection,
                                      monotonic=lambda: clock["now"].timestamp())
        self.assertTrue(fresh,
                        "Four hour-long rounds repeated only the same six failed buckets; all newer due buckets starved")

    def test_planning_a_backlog_keeps_bucket_paths_instead_of_all_partial_summaries(self):
        self.seed_start()
        self.config["MAX_BUCKETS_PER_ACCOUNT_PER_RUN"] = 1
        references, peak = [], 0
        for left, right in multi.windows(DAY, multi.ZoneInfo("UTC"), 30):
            multi.bucket_path(self.config, self.account, left).touch()

        def load(path, config, account, start, end):
            nonlocal peak
            summary = _TrackedSummary(merge_summaries([], start, end, dimension="ip"))
            references.append(weakref.ref(summary))
            peak = max(peak, sum(reference() is not None for reference in references))
            return {"active": {"summary": summary, "complete": False}, "last_errors": []}

        with patch.object(multi, "load_bucket", side_effect=load), redirect_stdout(StringIO()):
            result = multi.collect_account(self.config, self.account, MIDNIGHT + timedelta(days=1, minutes=5),
                                           session_factory=self.session,
                                           collector=lambda c, a, s, i, left, right, d: self.snapshot(left, right, count=0),
                                           monotonic=lambda: 0)
        self.assertEqual((result["processed"], result["remaining"]), (1, 47))
        self.assertEqual(len(references), 49)  # 48 planned buckets; only the selected one is reloaded.
        self.assertLessEqual(peak, 3)

    def test_each_attempt_and_alert_use_elapsed_time_and_snapshot_uses_completion_time(self):
        self.seed_start()
        self.config["MAX_BUCKETS_PER_ACCOUNT_PER_RUN"] = 2
        started = MIDNIGHT + timedelta(hours=4, minutes=5)
        elapsed = [0]

        def collector(config, account, session, identity, start, end, directory):
            elapsed[0] += 600
            return self.snapshot(start, end)

        with patch.object(multi, "dispatch_collection_alerts", return_value={"failed": 0, "pending": 0}) as alert:
            result = multi.collect_account(self.config, self.account, started, session_factory=self.session,
                                           collector=collector, monotonic=lambda: elapsed[0])
        self.assertEqual(result["processed"], 2)
        for index in (0, 1):
            state = multi.read_json(multi.bucket_path(self.config, self.account, MIDNIGHT + timedelta(minutes=30 * index)))
            self.assertEqual(state["last_attempt_at"], multi.iso(started + timedelta(minutes=10 * index)))
            self.assertEqual(state["active"]["collected_at"], multi.iso(started + timedelta(minutes=10 * (index + 1))))
        self.assertEqual(alert.call_args.args[4], started + timedelta(minutes=20))

    def test_slow_initial_query_does_not_count_as_a_post_delay_refresh(self):
        self.seed_start()
        elapsed = [0]
        started = MIDNIGHT + timedelta(minutes=35)

        def collector(config, account, session, identity, start, end, directory):
            elapsed[0] += 3600
            return self.snapshot(start, end)

        multi.collect_account(self.config, self.account, started, session_factory=self.session,
                              collector=collector, monotonic=lambda: elapsed[0])
        state = multi.read_json(multi.bucket_path(self.config, self.account, MIDNIGHT))
        self.assertFalse(state["refresh_done"], "A request started before the refresh delay must still receive a later query")
        self.assertEqual(state["active"]["collected_at"], multi.iso(started + timedelta(hours=1)))

    def test_full_slow_account_pipeline_never_moves_health_notifications_back_in_time(self):
        self.seed_start()
        self.config["LARK_ALERTS_ENABLED"] = True
        started = MIDNIGHT + timedelta(minutes=35)
        elapsed = [0]

        def collector(config, account, session, identity, start, end, directory):
            elapsed[0] += 600
            return self.snapshot(start, end)

        with patch.object(multi, "dispatch_collection_alerts", return_value={"failed": 0, "pending": 0}) as alert, redirect_stdout(StringIO()):
            result = multi._collect_one_account(self.config, self.account, started,
                {"session_factory": self.session, "collector": collector, "monotonic": lambda: elapsed[0]})
        self.assertEqual((result["processed"], result["failed"]), (1, 0))
        self.assertEqual(alert.call_count, 2)
        self.assertTrue(alert.call_args_list[0].args[3][0]["key"].startswith("bucket:"))
        self.assertEqual(alert.call_args_list[1].args[3][0]["key"], "account-health")
        expected = started + timedelta(minutes=10)
        self.assertEqual([call.args[4] for call in alert.call_args_list], [expected, expected])
        directory = multi.day_directory(self.config, self.account, DAY)
        self.assertEqual(multi.read_json(directory.parent / ".collection-health.json")["at"], multi.iso(expected))
        self.assertEqual(multi.read_json(directory / "collection-status.json")["at"], multi.iso(expected))


if __name__ == "__main__":
    unittest.main()
