"""Integration tests for the distributed scanner pipeline.

These tests verify the full data flow through Redis using the coordinator
helper functions.  They require a live Redis instance and are skipped
automatically when none is available.

Set STRELKA_TEST_REDIS to override the default host (localhost).
"""

import json
import os
import time

import pytest

redis_lib = pytest.importorskip('redis', reason='redis package not installed')

from strelka import coordinator as coord


REDIS_HOST = os.environ.get('STRELKA_TEST_REDIS', 'localhost')


@pytest.fixture
def redis():
    try:
        r = redis_lib.StrictRedis(host=REDIS_HOST, port=6379, db=15)
        r.ping()
    except Exception:
        pytest.skip('Redis not available')
    r.flushdb()
    yield r
    r.flushdb()


@pytest.mark.integration
def test_single_file_two_scanners_produce_event(redis):
    """
    Simulate dispatcher storing file_info + pending_scanners=2,
    then two scanner workers completing. Verify event assembled correctly and FIN sent.
    """
    root_id = 'test-root-1'
    file_uid = 'test-file-1'
    expire_at = int(time.time()) + 300

    # Simulate: pending:{root_id} = 1 (one file being processed)
    redis.set(f'pending:{root_id}', 1)
    redis.expireat(f'pending:{root_id}', expire_at)

    # Simulate dispatcher: store file_info, init pending_scanners=2
    file_dict = {
        'depth': 0, 'name': 'test.txt',
        'flavors': {'mime': ['text/plain']}, 'scanners': ['ScanA', 'ScanB'],
        'size': 11, 'source': '', 'tree': {'root': root_id},
    }
    coord.store_file_info(redis, root_id, file_uid, file_dict, expire_at)
    coord.init_pending_scanners(redis, root_id, file_uid, count=2, expire_at=expire_at)

    # Scanner A finishes
    coord.store_scan_result(redis, root_id, file_uid, 'a', {'elapsed': 0.1, 'flags': []}, expire_at)
    remaining = coord.decrement_pending_scanners(redis, root_id, file_uid)
    assert remaining == 1
    assert redis.llen(f'event:{root_id}') == 0  # no event yet

    # Scanner B finishes (last)
    coord.store_scan_result(redis, root_id, file_uid, 'b', {'elapsed': 0.2, 'flags': []}, expire_at)
    remaining = coord.decrement_pending_scanners(redis, root_id, file_uid)
    assert remaining == 0
    fin_sent = coord.assemble_and_push_event(redis, root_id, file_uid, 'test-version', expire_at)
    assert fin_sent is True

    # Verify event stream
    events = redis.lrange(f'event:{root_id}', 0, -1)
    assert len(events) == 2
    assert events[-1] == b'FIN'
    event = json.loads(events[0])
    assert event['scan']['a']['elapsed'] == pytest.approx(0.1)
    assert event['scan']['b']['elapsed'] == pytest.approx(0.2)
    assert event['file']['name'] == 'test.txt'
    assert event['backend']['release'] == 'test-version'


@pytest.mark.integration
def test_child_file_prevents_premature_fin(redis):
    """
    When a scanner extracts a child, pending:{root_id} must be incremented
    BEFORE the scanner's pending_scanners counter hits 0, or FIN fires too early.
    """
    root_id = 'test-root-2'
    parent_uid = 'file-parent'
    child_uid = 'file-child'
    expire_at = int(time.time()) + 300

    # Root file with one scanner
    redis.set(f'pending:{root_id}', 1)
    redis.expireat(f'pending:{root_id}', expire_at)
    coord.store_file_info(redis, root_id, parent_uid, {'depth': 0, 'name': 'archive.zip'}, expire_at)
    coord.init_pending_scanners(redis, root_id, parent_uid, count=1, expire_at=expire_at)

    # Scanner extracts a child → increment pending BEFORE decrementing scanner counter
    redis.incrby(f'pending:{root_id}', 1)  # now pending=2

    # Parent scanner completes (pending_scanners → 0)
    coord.store_scan_result(redis, root_id, parent_uid, 'zip', {'elapsed': 0.5, 'flags': []}, expire_at)
    remaining = coord.decrement_pending_scanners(redis, root_id, parent_uid)
    assert remaining == 0
    fin_sent = coord.assemble_and_push_event(redis, root_id, parent_uid, 'v1', expire_at)
    assert fin_sent is False  # pending:{root_id}=1 still (child not done)

    # Child file completes
    coord.store_file_info(redis, root_id, child_uid, {'depth': 1, 'name': 'inner.txt'}, expire_at)
    coord.init_pending_scanners(redis, root_id, child_uid, count=1, expire_at=expire_at)
    coord.store_scan_result(redis, root_id, child_uid, 'strings', {'elapsed': 0.1, 'flags': []}, expire_at)
    remaining = coord.decrement_pending_scanners(redis, root_id, child_uid)
    assert remaining == 0
    fin_sent = coord.assemble_and_push_event(redis, root_id, child_uid, 'v1', expire_at)
    assert fin_sent is True  # now pending=0

    events = redis.lrange(f'event:{root_id}', 0, -1)
    assert events[-1] == b'FIN'
    # Two file events: parent + child
    file_events = [json.loads(e) for e in events[:-1]]
    assert len(file_events) == 2


@pytest.mark.integration
def test_timed_out_scanner_does_not_block_event_assembly(redis):
    """A timed-out scanner still contributes a result so the event assembles."""
    root_id = 'test-root-3'
    file_uid = 'test-file-3'
    expire_at = int(time.time()) + 300

    redis.set(f'pending:{root_id}', 1)
    redis.expireat(f'pending:{root_id}', expire_at)
    coord.store_file_info(redis, root_id, file_uid, {'depth': 0, 'name': 'test.exe'}, expire_at)
    coord.init_pending_scanners(redis, root_id, file_uid, count=2, expire_at=expire_at)

    # Fast scanner finishes
    coord.store_scan_result(redis, root_id, file_uid, 'pe', {'elapsed': 0.1, 'flags': []}, expire_at)
    remaining = coord.decrement_pending_scanners(redis, root_id, file_uid)
    assert remaining == 1

    # Slow scanner times out (injected by watchdog)
    coord.store_scan_result(redis, root_id, file_uid, 'yara', {'elapsed': 0.0, 'flags': ['timed_out']}, expire_at)
    remaining = coord.decrement_pending_scanners(redis, root_id, file_uid)
    assert remaining == 0
    fin_sent = coord.assemble_and_push_event(redis, root_id, file_uid, 'v1', expire_at)
    assert fin_sent is True

    events = redis.lrange(f'event:{root_id}', 0, -1)
    event = json.loads(events[0])
    assert event['scan']['pe']['elapsed'] == pytest.approx(0.1)
    assert 'timed_out' in event['scan']['yara']['flags']
