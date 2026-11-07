"""Offline review of paging, partial snapshots and large streamed SQL input."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import time
import tracemalloc
import unittest
from unittest.mock import Mock, call, patch

import rds_multi as multi
from rds_config import ACCOUNT_DEFAULTS, DEFAULTS

UTC = timezone.utc
START = datetime(2026, 11, 5, 2, tzinfo=UTC)
END = START + timedelta(minutes=30)
GROUP = '/aws/rds/cluster/offline/audit'


def sql_event(identity, occurred=START, *, record_times=None):
    records = []
    for when in (record_times or [occurred]):
        records.append(f"{int(when.timestamp() * 1000000)},writer,app,192.0.2.22,99,23,QUERY,db,'UPDATE t SET n=1',0")
    return {'timestamp': int(occurred.timestamp() * 1000), 'eventId': identity,
            'logStreamName': 'writer', 'message': '\n'.join(records)}


def management_event(identity, when):
    raw = {'eventID': identity, 'eventName': 'ModifyDBInstance', 'eventTime': multi.iso(when),
           'eventSource': 'rds.amazonaws.com', 'sourceIPAddress': '192.0.2.23',
           'userIdentity': {'type': 'IAMUser', 'userName': 'offline'}, 'awsRegion': 'us-east-1'}
    return {'EventTime': when, 'EventId': identity, 'CloudTrailEvent': json.dumps(raw)}


class PaginationReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='rds-pagination-review-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = {**deepcopy(DEFAULTS), 'OUTPUT_DIRECTORY': str(self.root / 'output')}
        self.account = {**ACCOUNT_DEFAULTS, 'NAME': 'offline', 'ACCOUNT_ID': '000000000001',
                        'REGIONS': 'us-east-1'}
        self.logs, self.cloudtrail, self.session = Mock(), Mock(), Mock()
        self.logs.describe_log_groups.return_value = {'logGroups': [{'logGroupName': GROUP}]}
        self.cloudtrail.lookup_events.return_value = {'Events': []}
        self.session.client.side_effect = lambda service, **kwargs: {
            'logs': self.logs, 'cloudtrail': self.cloudtrail}[service]

    def collect(self, tag='attempt', start=START, end=END):
        directory = self.root / tag
        directory.mkdir()
        return multi.collect_bucket(self.config, self.account, self.session,
            {'Account': self.account['ACCOUNT_ID']}, start, end, directory)

    @staticmethod
    def total(snapshot, source='sql'):
        return sum(row['total'] for row in snapshot['summary']['actors'] if row['source_kind'] == source)

    def test_empty_pages_continue_and_repeated_events_count_once(self):
        self.logs.filter_log_events.side_effect = [
            {'events': [], 'nextToken': 'empty-first'},
            {'events': [sql_event('one')], 'nextToken': 'nonempty'},
            {'events': [], 'nextToken': 'empty-middle'},
            {'events': [sql_event('one'), sql_event('two')]},
        ]
        result = self.collect()
        self.assertTrue(result['complete'])
        self.assertEqual(self.total(result), 2)
        self.assertEqual(result['summary']['coverage']['duplicate_cloudwatch_events'], 1)
        self.assertEqual(self.logs.filter_log_events.call_count, 4)

    def test_failed_later_page_retains_partial_counts_but_never_marks_snapshot_complete(self):
        self.logs.filter_log_events.side_effect = [
            {'events': [sql_event('one')], 'nextToken': 'later'}, RuntimeError('simulated service failure')]
        first = self.collect()
        self.assertFalse(first['complete'])
        self.assertEqual(self.total(first), 1)
        self.assertTrue(first['errors'])
        self.logs.filter_log_events.side_effect = [
            {'events': [sql_event('one')], 'nextToken': 'later'}, {'events': [sql_event('two')]}]
        recovered = self.collect('recovered')
        self.assertTrue(recovered['complete'])
        self.assertEqual(self.total(recovered), 2)

    def test_repeated_cursor_is_incomplete_even_if_all_seen_sql_is_parseable(self):
        self.logs.filter_log_events.side_effect = [
            {'events': [sql_event('one')], 'nextToken': 'same'},
            {'events': [sql_event('one')], 'nextToken': 'same'}]
        result = self.collect()
        self.assertFalse(result['complete'])
        self.assertEqual(self.total(result), 1)
        self.assertTrue(any(error['error_type'] == 'RuntimeError' for error in result['errors']))

    def test_adjacent_cloudwatch_and_cloudtrail_windows_do_not_double_count_boundaries(self):
        boundary = END
        events = [sql_event('before', boundary - timedelta(milliseconds=1)),
                  sql_event('at-boundary', boundary)]
        management = [management_event('before', boundary - timedelta(milliseconds=1)),
                      management_event('at-boundary', boundary)]
        self.logs.filter_log_events.return_value = {'events': events}
        self.cloudtrail.lookup_events.return_value = {'Events': management}
        left = self.collect('left')
        right = self.collect('right', start=END, end=END + timedelta(minutes=30))
        for source in ('sql', 'management'):
            self.assertEqual(self.total(left, source), 1)
            self.assertEqual(self.total(right, source), 1)
        self.assertTrue(left['complete'] and right['complete'])

    def test_batched_sql_uses_cloudwatch_message_time_rather_than_each_record_time(self):
        # Characterize the current query semantics explicitly: a single message
        # is assigned wholly by the CloudWatch timestamp, even if SQL headers
        # span the boundary. It is counted once across adjacent message windows.
        event = sql_event('batch', END - timedelta(milliseconds=1),
                          record_times=[END - timedelta(seconds=1), END + timedelta(seconds=1)])
        self.logs.filter_log_events.return_value = {'events': [event]}
        left = self.collect('batch-left')
        right = self.collect('batch-right', start=END, end=END + timedelta(minutes=30))
        self.assertEqual(self.total(left), 2)
        self.assertEqual(self.total(right), 0)
        self.assertTrue(left['complete'] and right['complete'])

    def test_single_page_segments_delay_before_each_cloudtrail_request(self):
        self.logs.filter_log_events.return_value = {'events': []}
        ordering = Mock()
        ordering.attach_mock(self.cloudtrail.lookup_events, 'request')
        with patch('rds_audit.time.sleep') as sleeper:
            ordering.attach_mock(sleeper, 'sleep')
            for index in range(3):
                result = self.collect('one-page-' + str(index),
                    start=START + timedelta(minutes=30 * index),
                    end=END + timedelta(minutes=30 * index))
                self.assertTrue(result['complete'])
        self.assertEqual(self.cloudtrail.lookup_events.call_count, 3)
        self.assertEqual([event[0] for event in ordering.mock_calls], ['sleep', 'request'] * 3)
        self.assertEqual(sleeper.call_args_list, [call(0.55)] * 3)

    def test_multi_page_cloudtrail_requests_each_delay_including_empty_pages(self):
        self.logs.filter_log_events.return_value = {'events': []}
        self.cloudtrail.lookup_events.side_effect = [
            {'Events': [], 'NextToken': 'empty-first'},
            {'Events': [management_event('one', START)], 'NextToken': 'second'},
            {'Events': [management_event('one', START), management_event('two', START)]},
        ]
        ordering = Mock()
        ordering.attach_mock(self.cloudtrail.lookup_events, 'request')
        with patch('rds_audit.time.sleep') as sleeper:
            ordering.attach_mock(sleeper, 'sleep')
            result = self.collect('cloudtrail-paged')
        self.assertTrue(result['complete'])
        self.assertEqual(self.total(result, 'management'), 2)
        self.assertEqual([event[0] for event in ordering.mock_calls], ['sleep', 'request'] * 3)
        self.assertEqual(sleeper.call_args_list, [call(0.55)] * 3)
        self.assertEqual(self.cloudtrail.lookup_events.call_args_list[1].kwargs['NextToken'], 'empty-first')
        self.assertEqual(self.cloudtrail.lookup_events.call_args_list[2].kwargs['NextToken'], 'second')

    @unittest.skipUnless(os.environ.get('RDS_REVIEW_STRESS') == '1', 'Explicit offline 100k-event review')
    def test_streams_100000_unique_events_with_empty_pages_and_duplicates(self):
        unique, page, previous, duplicates = 0, 0, None, 0

        def next_page(**request):
            nonlocal unique, page, previous, duplicates
            if page:
                self.assertEqual(request['nextToken'], str(page))
            events = []
            if page % 11 != 0:
                if previous is not None:
                    events.append(previous)
                    duplicates += 1
                for index in range(unique, min(100000, unique + 500)):
                    events.append(sql_event(str(index)))
                unique = min(100000, unique + 500)
                previous = events[-1]
            page += 1
            response = {'events': events}
            if unique < 100000:
                response['nextToken'] = str(page)
            return response

        self.logs.filter_log_events.side_effect = next_page
        tracemalloc.start()
        started = time.monotonic()
        try:
            result = self.collect('stress-100k')
            elapsed = time.monotonic() - started
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertTrue(result['complete'])
        self.assertEqual(self.total(result), 100000)
        self.assertEqual(result['summary']['coverage']['duplicate_cloudwatch_events'], duplicates)
        self.assertEqual(result['summary']['coverage']['audit_cloudwatch_events'], 100000)
        print(f'OFFLINE_STRESS unique=100000 pages={page} duplicate_events={duplicates} '
              f'elapsed_seconds={elapsed:.3f} traced_python_peak_mib={peak / 1024 / 1024:.3f}')


if __name__ == '__main__':
    unittest.main()
