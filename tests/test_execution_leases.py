"""Synthetic executor races, process death and lease ownership regressions."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import threading
import time

import pytest
from test_approvals import AGENT, HUMAN, Clock, gateway, request

from mcp_policy_gateway.store import ApprovalState, SyntheticFreezeUpstream


def approved(db, clock):
    service = gateway(db, clock=clock)
    request_id = request(service)["request_id"]
    assert service.decide_freeze(HUMAN, request_id, approve=True, note="synthetic check")["ok"]
    return service, request_id


class BlockingUpstream(SyntheticFreezeUpstream):
    def __init__(self, db, entered, release, fail=False):
        super().__init__(db)
        self.entered, self.release, self.fail = entered, release, fail

    def apply_freeze(self, request_id, account_id):
        super().apply_freeze(request_id, account_id)
        self.entered.set()
        if not self.release.wait(timeout=10):
            raise TimeoutError("test did not release upstream")
        if self.fail:
            raise TimeoutError("synthetic lost response")


def worker(db, clock, request_id, entered, release, results, fail=False):
    try:
        service = gateway(db, clock, BlockingUpstream(db, entered, release, fail))
        results.append(service.execute_freeze(HUMAN, request_id))
    except BaseException as exc:
        results.append(exc)


def test_live_lease_blocks_duplicate_call_and_is_not_public(tmp_path):
    db, clock = tmp_path / "gateway.sqlite3", Clock()
    service, request_id = approved(db, clock)
    entered, release = threading.Event(), threading.Event()
    results = []
    thread = threading.Thread(
        target=worker, args=(db, clock, request_id, entered, release, results)
    )
    thread.start()
    try:
        assert entered.wait(timeout=5)
        busy = service.execute_freeze(HUMAN, request_id)
        assert (busy["ok"], busy["reason"]) == (False, "execution_in_progress")
        assert busy["retry_after_seconds"] == 30
        assert service.upstream.apply_calls(request_id) == 1
        public = json.dumps(service.store.get(request_id).public_view())
        assert "lease" not in public
        assert "owner" not in public
        assert service.audit_log(request_id)[-1]["reason"] == "execution_in_progress"
    finally:
        release.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert results[0]["reason"] == "executed"
    assert service.execute_freeze(HUMAN, request_id)["reason"] == "already_executed"
    assert service.upstream.apply_calls(request_id) == 1
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM execution_leases").fetchone()[0] == 0


@pytest.mark.parametrize("fail", [False, True])
def test_stale_executor_cannot_finalize_or_release_successor_lease(tmp_path, fail):
    db, clock = tmp_path / "gateway.sqlite3", Clock()
    service, request_id = approved(db, clock)
    entered1, release1, entered2, release2 = [threading.Event() for _ in range(4)]
    results1, results2 = [], []
    first = threading.Thread(
        target=worker, args=(db, clock, request_id, entered1, release1, results1, fail)
    )
    second = threading.Thread(
        target=worker, args=(db, clock, request_id, entered2, release2, results2)
    )
    first.start()
    try:
        assert entered1.wait(timeout=5)
        clock.now += 30  # exact expiry permits a successor, even if the first is alive
        second.start()
        assert entered2.wait(timeout=5)
        release1.set()
        first.join(timeout=5)
        assert not first.is_alive()
        assert (results1[0]["ok"], results1[0]["reason"]) == (False, "execution_lease_lost")
        assert service.store.get(request_id).state is ApprovalState.EXECUTING
        # Neither a late success nor a late exception may release the successor's lease.
        assert service.execute_freeze(HUMAN, request_id)["reason"] == "execution_in_progress"
        assert service.upstream.apply_calls(request_id) == 2
    finally:
        release1.set()
        release2.set()
        first.join(timeout=5)
        if second.ident is not None:
            second.join(timeout=5)
    assert not second.is_alive()
    assert results2[0]["reason"] == "executed"
    assert service.upstream.effect_count("acct_red") == 1


def test_expired_owner_cannot_finalize_without_a_successor(tmp_path):
    db, clock = tmp_path / "gateway.sqlite3", Clock()
    service, request_id = approved(db, clock)
    entered, release = threading.Event(), threading.Event()
    results = []
    thread = threading.Thread(
        target=worker, args=(db, clock, request_id, entered, release, results)
    )
    thread.start()
    try:
        assert entered.wait(timeout=5)
        clock.now += 30
    finally:
        release.set()
        thread.join(timeout=5)
    assert results[0]["reason"] == "execution_lease_lost"
    assert service.store.get(request_id).state is ApprovalState.EXECUTING
    assert service.execute_freeze(HUMAN, request_id)["reason"] == "executed"
    assert service.upstream.effect_count("acct_red") == 1


def test_process_death_after_effect_recovers_only_after_lease_expiry(tmp_path):
    db, clock = tmp_path / "gateway.sqlite3", Clock()
    service, request_id = approved(db, clock)
    marker = tmp_path / "upstream-applied"
    script = """
import sys, time
from pathlib import Path
from mcp_policy_gateway.models import Principal
from mcp_policy_gateway.service import GatewayService
from mcp_policy_gateway.store import ApprovalStore, SyntheticFreezeUpstream
class CrashPoint(SyntheticFreezeUpstream):
    def apply_freeze(self, request_id, account_id):
        super().apply_freeze(request_id, account_id)
        Path(sys.argv[3]).write_text('applied')
        time.sleep(60)
service = GatewayService(store=ApprovalStore(sys.argv[1]), upstream=CrashPoint(sys.argv[1]),
                         clock=lambda: 1_000_000.0)
service.execute_freeze(Principal('human-01', 'tenant_red',
    frozenset({'gateway:approve_account_freeze'})), sys.argv[2])
"""
    process = subprocess.Popen([sys.executable, "-c", script, str(db), request_id, str(marker)])
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists(), "child never reached the crash point"
    finally:
        process.kill()
        process.wait(timeout=5)
    assert process.returncode != 0
    restarted = gateway(db, clock=clock)
    assert restarted.execute_freeze(HUMAN, request_id)["reason"] == "execution_in_progress"
    clock.now += 29
    assert restarted.execute_freeze(HUMAN, request_id)["retry_after_seconds"] == 1
    clock.now += 1
    assert restarted.execute_freeze(HUMAN, request_id)["reason"] == "executed"
    assert restarted.upstream.apply_calls(request_id) == 2
    assert restarted.upstream.effect_count("acct_red") == 1
    assert "execution_resumed" in [e["reason"] for e in restarted.audit_log(request_id)]


def test_upgrade_resumes_legacy_executing_row_without_a_lease(tmp_path):
    db, clock = tmp_path / "gateway.sqlite3", Clock()
    service, request_id = approved(db, clock)
    with service.store.transaction():
        service.store.transition(request_id, ApprovalState.APPROVED, ApprovalState.EXECUTING)
    service.store.close()
    with sqlite3.connect(db) as connection:
        connection.execute("DROP TABLE IF EXISTS execution_leases")
    upgraded = gateway(db, clock=clock)
    assert upgraded.execute_freeze(HUMAN, request_id)["reason"] == "executed"
    assert upgraded.upstream.effect_count("acct_red") == 1


def test_lock_wait_crossing_lease_expiry_can_resume(tmp_path):
    db, clock = tmp_path / "gateway.sqlite3", Clock()
    service, request_id = approved(db, clock)
    with service.store.transaction():
        service.store.transition(request_id, ApprovalState.APPROVED, ApprovalState.EXECUTING)
        assert service.store.claim_execution(request_id, "dead-worker", clock.now, 30)
    clock.now += 29
    locked, release = threading.Event(), threading.Event()
    errors = []

    def hold_lock():
        try:
            connection = sqlite3.connect(db, isolation_level=None)
            connection.execute("BEGIN IMMEDIATE")
            locked.set()
            assert release.wait(timeout=5)
            clock.now += 1
            connection.execute("COMMIT")
            connection.close()
        except BaseException as exc:
            errors.append(exc)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert locked.wait(timeout=5)
    timer = threading.Timer(0.2, release.set)
    timer.start()
    try:
        result = service.execute_freeze(HUMAN, request_id)
    finally:
        release.set()
        holder.join(timeout=5)
        timer.join(timeout=5)
    assert not errors
    assert result["reason"] == "executed"
    assert service.upstream.apply_calls(request_id) == 1


def test_unprivileged_executor_cannot_claim_a_lease(tmp_path):
    db, clock = tmp_path / "gateway.sqlite3", Clock()
    service, request_id = approved(db, clock)
    assert service.execute_freeze(AGENT, request_id)["reason"] == "missing_approver_scope"
    assert service.store.execution_lease(request_id) is None
    assert service.store.get(request_id).state is ApprovalState.APPROVED
    assert service.upstream.apply_calls(request_id) == 0


def test_completion_audit_failure_rolls_back_state_and_lease_release(tmp_path, monkeypatch):
    db, clock = tmp_path / "gateway.sqlite3", Clock()
    service, request_id = approved(db, clock)
    original = service.store.append_audit

    def unavailable(event, recorded_at):
        if event.reason == "executed":
            raise RuntimeError("synthetic audit failure")
        return original(event, recorded_at)

    monkeypatch.setattr(service.store, "append_audit", unavailable)
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        service.execute_freeze(HUMAN, request_id)
    assert service.store.get(request_id).state is ApprovalState.EXECUTING
    assert service.store.execution_lease(request_id) is not None
    assert service.upstream.effect_count("acct_red") == 1
    monkeypatch.setattr(service.store, "append_audit", original)
    assert service.execute_freeze(HUMAN, request_id)["reason"] == "execution_in_progress"
    clock.now += 30
    assert service.execute_freeze(HUMAN, request_id)["reason"] == "executed"
    assert service.upstream.effect_count("acct_red") == 1


def test_claim_and_audit_roll_back_together(tmp_path, monkeypatch):
    db, clock = tmp_path / "gateway.sqlite3", Clock()
    service, request_id = approved(db, clock)
    original = service.store.append_audit

    def unavailable(event, recorded_at):
        if event.reason == "execution_started":
            raise RuntimeError("synthetic audit failure")
        return original(event, recorded_at)

    monkeypatch.setattr(service.store, "append_audit", unavailable)
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        service.execute_freeze(HUMAN, request_id)
    assert service.store.get(request_id).state is ApprovalState.APPROVED
    assert service.upstream.apply_calls(request_id) == 0
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM execution_leases").fetchone()[0] == 0
    monkeypatch.setattr(service.store, "append_audit", original)
    assert service.execute_freeze(HUMAN, request_id)["reason"] == "executed"
