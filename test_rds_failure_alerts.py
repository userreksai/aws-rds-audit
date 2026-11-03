"""Persistent operational notifications use mock senders, never real webhooks."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from rds_failure_alerts import sync_collection_alerts


class CollectionFailureAlertTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / ".lark-state.json"
        self.now = datetime(2026, 11, 3, 3, 0, tzinfo=timezone.utc)
        self.config = {
            "LARK_ALERTS_ENABLED": True,
            "LARK_WEBHOOK_URL": "https://open.larksuite.com/open-apis/bot/v2/hook/DO-NOT-PERSIST-URL",
            "LARK_SIGNING_SECRET": "DO-NOT-PERSIST-SIGNING-SECRET",
            "LARK_ALERT_AFTER_FAILURES": 2,
            "LARK_ALERT_REPEAT_MINUTES": 60,
            "LARK_NOTIFICATION_RETRY_MINUTES": 5,
            "RETENTION_DAYS": 7,
            "TIMEZONE": "Asia/Shanghai",
        }
        self.account = {"NAME": "production", "ACCOUNT_ID": "123456789012", "REGIONS": "ap-east-1"}
        self.sender = Mock(return_value={"code": 0})

    def observation(self, key="bucket:scope:2026-11-03T02:00:00Z", *, failed=True,
                    failures=2, attempts=2, start="2026-11-03T02:00:00Z", end="2026-11-03T02:30:00Z"):
        item = {"key": key, "failed": failed, "consecutive_failures": failures if failed else 0,
                "attempts": attempts, "error_types": ["AccessDeniedException"] if failed else []}
        if start is not None:
            item["bucket_start"] = start
        if end is not None:
            item["bucket_end"] = end
        return item

    def sync(self, observations=(), *, minutes=0, sender=None, config=None, collection_scope=None):
        return sync_collection_alerts(self.config if config is None else config, self.account, self.state,
                                      list(observations), self.now + timedelta(minutes=minutes),
                                      sender=self.sender if sender is None else sender,
                                      collection_scope=collection_scope)

    def assert_stats(self, result, sent=0, pending=0, failed=0):
        self.assertEqual({key: result[key] for key in ("sent", "pending", "failed")},
                         {"sent": sent, "pending": pending, "failed": failed})

    def kind(self, call):
        return call.args[0].get("kind") or call.args[0].get("type") or ""

    def test_first_failure_silent_second_failure_opens_one_incident(self):
        self.assert_stats(self.sync([self.observation(failures=1, attempts=1)]))
        self.sender.assert_not_called()
        self.assert_stats(self.sync([self.observation()], minutes=1), sent=1)
        self.sender.assert_called_once()
        payload = self.sender.call_args.args[0]
        self.assertEqual(payload["account_id"], self.account["ACCOUNT_ID"])
        self.assertTrue(payload["event_id"])
        self.assertNotIn("recover", self.kind(self.sender.call_args))

    def test_duplicate_observations_are_throttled_and_no_observation_reminder_runs(self):
        self.assert_stats(self.sync([self.observation()]), sent=1)
        self.assert_stats(self.sync([self.observation(attempts=5, failures=5)], minutes=1))
        self.assert_stats(self.sync(minutes=59))
        self.assert_stats(self.sync(minutes=60), sent=1)
        self.assertEqual(self.sender.call_count, 2)
        self.assert_stats(self.sync(minutes=61))

    def test_send_failure_retries_from_persisted_queue_without_new_observations(self):
        self.sender.side_effect = RuntimeError("DO-NOT-PERSIST-PROVIDER-TEXT")
        self.assert_stats(self.sync([self.observation()]), pending=1, failed=1)
        first_event_id = self.sender.call_args.args[0]["event_id"]
        self.assertTrue(self.state.is_file())
        self.assertNotIn("DO-NOT-PERSIST-PROVIDER-TEXT", self.state.read_text(encoding="utf-8"))
        self.sender.side_effect = None
        self.assert_stats(self.sync(minutes=4), pending=1)
        self.assertEqual(self.sender.call_count, 1)
        self.assert_stats(self.sync(minutes=5), sent=1)
        self.assertEqual(self.sender.call_args.args[0]["event_id"], first_event_id)
        self.assert_stats(self.sync(minutes=6))

    def test_recovery_cancels_failure_that_was_never_delivered(self):
        self.sender.side_effect = OSError("unavailable")
        self.assert_stats(self.sync([self.observation()]), pending=1, failed=1)
        self.sender.side_effect = None
        self.assert_stats(self.sync([self.observation(failed=False)], minutes=1))
        self.assert_stats(self.sync(minutes=6))
        self.assertEqual(self.sender.call_count, 1)

    def test_successful_incident_gets_recovery_and_recovery_notification_retries(self):
        self.assert_stats(self.sync([self.observation()]), sent=1)
        self.sender.side_effect = RuntimeError("transport unavailable")
        self.assert_stats(self.sync([self.observation(failed=False)], minutes=2), pending=1, failed=1)
        recovery_id = self.sender.call_args.args[0]["event_id"]
        self.assertIn("recover", self.kind(self.sender.call_args))
        self.sender.side_effect = None
        self.assert_stats(self.sync(minutes=7), sent=1)
        self.assertEqual(self.sender.call_args.args[0]["event_id"], recovery_id)
        self.assert_stats(self.sync([self.observation(failed=False)], minutes=8))
        self.assert_stats(self.sync(minutes=120))
        self.assertEqual(self.sender.call_count, 3)

    def test_many_buckets_send_one_account_summary(self):
        observations = [self.observation(key=f"bucket:scope:{number}") for number in range(6)]
        self.assert_stats(self.sync(observations), sent=1)
        self.sender.assert_called_once()
        self.assertTrue(self.sender.call_args.args[0]["event_id"])
        self.assert_stats(self.sync(observations, minutes=1))

    def test_same_account_failure_and_recovery_groups_are_separate(self):
        self.assert_stats(self.sync([self.observation(key="bucket:scope:a")]), sent=1)
        result = self.sync([self.observation(key="bucket:scope:a", failed=False),
                            self.observation(key="bucket:scope:b")], minutes=2)
        self.assert_stats(result, sent=2)
        kinds = [self.kind(call) for call in self.sender.call_args_list[1:]]
        self.assertEqual(sum("recover" in kind for kind in kinds), 1)

    def test_new_failure_after_recovery_has_new_event_identifier(self):
        self.sync([self.observation()])
        first_id = self.sender.call_args.args[0]["event_id"]
        self.sync([self.observation(failed=False)], minutes=1)
        self.assert_stats(self.sync([self.observation()], minutes=3), sent=1)
        self.assertNotEqual(first_id, self.sender.call_args.args[0]["event_id"])

    def test_expired_bucket_pending_is_pruned_and_health_stays_bounded(self):
        self.sender.side_effect = OSError("unavailable")
        health = self.observation(key="account-health", start=None, end=None)
        self.assert_stats(self.sync([self.observation(), health]), pending=2, failed=1)
        self.sender.side_effect = None
        self.assert_stats(self.sync(minutes=8 * 24 * 60), sent=1)
        incidents = json.loads(self.state.read_text(encoding="utf-8"))["incidents"]
        self.assertEqual(len(incidents), 1)
        self.assertTrue(next(iter(incidents.values()))["account_health"])
        for index in range(15):
            self.sync([self.observation(key="account-health", start=None, end=None,
                                        failed=False)], minutes=8 * 24 * 60 + index + 1)
        self.assertLess(self.state.stat().st_size, 12_000)

    def test_enabled_missing_webhook_keeps_pending_and_counts_failure_without_leaks(self):
        config = {**self.config, "LARK_WEBHOOK_URL": ""}
        self.assert_stats(self.sync([self.observation()], config=config), pending=1, failed=1)
        self.sender.assert_not_called()
        self.assert_stats(self.sync(minutes=5), sent=1)
        text = self.state.read_text(encoding="utf-8")
        self.assertNotIn("DO-NOT-PERSIST", text)

    def test_disabled_is_silent_and_default_config_is_disabled(self):
        for config in ({**self.config, "LARK_ALERTS_ENABLED": False}, {}):
            self.assert_stats(self.sync([self.observation()], config=config))
        self.sender.assert_not_called()

    def test_only_safe_observation_metadata_is_persisted(self):
        observation = self.observation()
        observation.update(sql="DO-NOT-PERSIST-SQL", secret="DO-NOT-PERSIST-KEY",
                           provider_text="DO-NOT-PERSIST-PROVIDER",
                           error_types=["AccessDeniedException", "DO-NOT-PERSIST=ERROR", "SQL TEXT"])
        self.sender.side_effect = RuntimeError("DO-NOT-PERSIST-RAW-EXCEPTION")
        self.sync([observation])
        text = self.state.read_text(encoding="utf-8")
        self.assertNotIn("DO-NOT-PERSIST", text)
        self.assertNotIn("SQL TEXT", text)
        self.assertIn("AccessDeniedException", text)

    def test_scope_migration_discards_old_pending_failure_reminder_and_recovery(self):
        for old_scope in (None, "old-v2-scope"):
            for phase in ("pending_failure", "reminder", "pending_recovery"):
                with self.subTest(old_scope=old_scope, phase=phase):
                    self.state.unlink(missing_ok=True)
                    self.sender.reset_mock()
                    self.sender.side_effect = None
                    if phase == "pending_failure":
                        self.sender.side_effect = RuntimeError("unavailable")
                        self.assert_stats(self.sync([self.observation()], collection_scope=old_scope), pending=1, failed=1)
                    else:
                        self.assert_stats(self.sync([self.observation()], collection_scope=old_scope), sent=1)
                        if phase == "pending_recovery":
                            self.sender.side_effect = RuntimeError("unavailable")
                            self.assert_stats(self.sync([self.observation(failed=False)], minutes=1,
                                                       collection_scope=old_scope), pending=1, failed=1)
                    if old_scope is None:
                        # Simulate a file from before the collection_scope field
                        # existed, not merely a newly-written null field.
                        legacy = json.loads(self.state.read_text(encoding="utf-8"))
                        legacy.pop("collection_scope", None)
                        self.state.write_text(json.dumps(legacy), encoding="utf-8")
                    self.sender.reset_mock()
                    self.sender.side_effect = None
                    self.assert_stats(self.sync(minutes=61, collection_scope="literal-ip-v3-scope"))
                    self.sender.assert_not_called()
                    migrated = json.loads(self.state.read_text(encoding="utf-8"))
                    self.assertEqual(migrated["collection_scope"], "literal-ip-v3-scope")
                    self.assertEqual(migrated["incidents"], {})
                    self.assertEqual(migrated["account_id"], self.account["ACCOUNT_ID"])

    def test_new_scope_establishes_its_own_first_and_second_failure(self):
        self.assert_stats(self.sync([self.observation(failures=9, attempts=9)], collection_scope="old-scope"), sent=1)
        self.sender.reset_mock()
        self.assert_stats(self.sync([self.observation(failures=1, attempts=1)], minutes=1,
                                   collection_scope="new-scope"))
        self.sender.assert_not_called()
        item = next(iter(json.loads(self.state.read_text(encoding="utf-8"))["incidents"].values()))
        self.assertFalse(item["open"])
        self.assertEqual(item["consecutive_failures"], 1)
        self.assert_stats(self.sync([self.observation(failures=2, attempts=2)], minutes=2,
                                   collection_scope="new-scope"), sent=1)
        self.sender.assert_called_once()
        self.assertNotIn("recover", self.kind(self.sender.call_args))

    def test_same_scope_preserves_pending_retry_and_event_identity_across_rounds(self):
        self.sender.side_effect = OSError("unavailable")
        self.assert_stats(self.sync([self.observation()], collection_scope="same-scope"), pending=1, failed=1)
        event_id = self.sender.call_args.args[0]["event_id"]
        self.sender.side_effect = None
        self.assert_stats(self.sync(minutes=4, collection_scope="same-scope"), pending=1)
        self.assertEqual(self.sender.call_count, 1)
        self.assert_stats(self.sync(minutes=5, collection_scope="same-scope"), sent=1)
        self.assertEqual(self.sender.call_args.args[0]["event_id"], event_id)
        self.assertEqual(json.loads(self.state.read_text(encoding="utf-8"))["collection_scope"], "same-scope")

    def test_legacy_call_without_scope_does_not_erase_a_previously_bound_scope(self):
        self.assert_stats(self.sync([self.observation(failures=1, attempts=1)], collection_scope="bound-scope"))
        self.assert_stats(self.sync([self.observation()], minutes=1), sent=1)
        self.assertEqual(json.loads(self.state.read_text(encoding="utf-8"))["collection_scope"], "bound-scope")

    def test_same_scope_does_not_override_account_isolation(self):
        self.assert_stats(self.sync([self.observation()], collection_scope="same-scope"), sent=1)
        self.sender.reset_mock()
        other = {**self.account, "ACCOUNT_ID": "210987654321", "NAME": "other"}
        result = sync_collection_alerts(self.config, other, self.state, [], self.now + timedelta(minutes=61),
                                         sender=self.sender, collection_scope="same-scope")
        self.assert_stats(result)
        self.sender.assert_not_called()
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(state["account_id"], other["ACCOUNT_ID"])
        self.assertEqual(state["collection_scope"], "same-scope")
        self.assertEqual(state["incidents"], {})
        result = sync_collection_alerts(self.config, other, self.state, [self.observation(failures=1, attempts=1)],
                                         self.now + timedelta(minutes=62), sender=self.sender,
                                         collection_scope="same-scope")
        self.assert_stats(result)
        self.sender.assert_not_called()


if __name__ == "__main__":
    unittest.main()
