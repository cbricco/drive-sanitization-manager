from __future__ import annotations

from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import pickle
import stat
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import execution_attempt_journal as attempt


IDENTITY = (
    "xhnd_" + ("a" * 64),
    "/synthetic/b3fd",
    "8:0",
    "sha256:" + ("b" * 64),
)
XELI = "xeli_" + ("c" * 64)
AUTH_ID = "xeauth_" + ("d" * 64)


def authorization_record():
    import executor_authorization as exauth

    base = exauth.ExecutorAuthorizationRecord(
        authorization_id=AUTH_ID,
        policy_version=exauth.EXECUTOR_AUTHORIZATION_POLICY_VERSION,
        schema_version=exauth.EXECUTOR_AUTHORIZATION_SCHEMA_VERSION,
        state=exauth.EXECUTOR_AUTHORIZATION_STATE_RESERVED,
        lease_binding_id=XELI,
        handoff_id=IDENTITY[0],
        target_path=IDENTITY[1],
        target_major_minor=IDENTITY[2],
        target_binding_hash=IDENTITY[3],
        gate_id="xgate_" + ("e" * 64),
        binding_id="xeb_" + ("f" * 64),
        journal_policy_version="journal-policy",
        journal_schema_version=1,
        journal_state="completed",
        journal_entry_hash="sha256:" + ("1" * 64),
        approval_id="approval-synthetic",
        request_id="request-synthetic",
        request_hash="sha256:" + ("2" * 64),
        record_snapshot_hash="sha256:" + ("3" * 64),
        internal_record_id="record-synthetic",
        method_profile_id="synthetic-method",
        operation="sanitize",
        authorized_at_utc="2026-09-02T09:00:00.000000Z",
        reserved_at_utc="2026-09-02T09:01:00.000000Z",
        record_hash="synthetic",
    )
    return replace(
        base,
        record_hash=exauth._canonical_hash(
            exauth._record_payload(base)
        ),
    )


class FakeClaimScope:
    def __init__(self, events):
        self._entered = True
        self.events = events
        self.identity = IDENTITY

    def revalidate_descriptor(self):
        self.events.append("descriptor")
        return IDENTITY[2]


class FakeLease:
    def __init__(self):
        self._consumed = True
        self._arguments = {}
        self._handoff_id = IDENTITY[0]
        self._target_path = IDENTITY[1]
        self._target_major_minor = IDENTITY[2]
        self._target_binding_hash = IDENTITY[3]


class FakeLeaseScope:
    def __init__(self, claim_scope):
        self._entered = True
        self._claim_scope = claim_scope


class FakeAuthorizationScope:
    def __init__(self, record, events):
        self._entered = True
        self.current_record = record
        self.events = events

    @property
    def record(self):
        self.events.append("authorization")
        return self.current_record


class FakeCapability:
    def __init__(self, auth_record, events):
        self._lease = FakeLease()
        self._lease_scope = FakeLeaseScope(
            FakeClaimScope(events)
        )
        self._authorization_scope = FakeAuthorizationScope(
            auth_record,
            events,
        )
        self._identity = IDENTITY
        self._lease_binding_id = XELI
        self._authorization_id = AUTH_ID
        self.active = True
        self.execution_authorized = False
        self.execution_supported = False
        self.executor_eligible = False
        self.execution_performed = False
        self.lease_consumed = True
        self.requires_future_executor = True


class TrackingStore(attempt.DurableExecutionAttemptJournal):
    def __init__(self, path, events):
        super().__init__(path)
        self.events = events

    def _open_lock(self):
        self.events.append("attempt-lock")
        return super()._open_lock()

    def _write_locked(self, entries):
        self.events.append("persist")
        return super()._write_locked(entries)

    def _close_lock(self, fd):
        self.events.append("attempt-unlock")
        return super()._close_lock(fd)


class ExecutionAttemptJournalTests(unittest.TestCase):
    def private_dir(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        os.chmod(temp.name, 0o700)
        return Path(temp.name)

    def patches_for_fake(self):
        return (
            patch.object(attempt, "_CAPABILITY_TYPE", FakeCapability),
            patch.object(attempt, "_LEASE_TYPE", FakeLease),
            patch.object(attempt, "_LEASE_SCOPE_TYPE", FakeLeaseScope),
            patch.object(
                attempt,
                "_AUTH_SCOPE_TYPE",
                FakeAuthorizationScope,
            ),
            patch.object(attempt, "_CLAIM_SCOPE_TYPE", FakeClaimScope),
            patch.object(attempt, "_STORE_TYPE", TrackingStore),
            patch.object(
                attempt.leases,
                "_internal_integrity_binding_valid",
                return_value=True,
            ),
            patch.object(
                attempt.exauth,
                "_record_integrity_valid",
                return_value=True,
            ),
        )

    def start_fake_patches(self):
        managers = self.patches_for_fake()
        for manager in managers:
            manager.start()
            self.addCleanup(manager.stop)

    def test_attempt_record_is_noncopyable_and_nonserializable(self):
        auth = authorization_record()
        record = attempt._build_record(
            authorization=auth,
            attempt_id="xeattempt_" + ("4" * 64),
            attempted_at_utc="2026-09-02T10:00:00.000000Z",
        )
        with self.assertRaises(attempt.ExecutionAttemptError):
            copy.copy(record)
        with self.assertRaises(attempt.ExecutionAttemptError):
            copy.deepcopy(record)
        with self.assertRaises(attempt.ExecutionAttemptError):
            pickle.dumps(record)

    def test_record_semantics_are_attempting_only_and_non_authorizing(self):
        auth = authorization_record()
        record = attempt._build_record(
            authorization=auth,
            attempt_id="xeattempt_" + ("5" * 64),
            attempted_at_utc="2026-09-02T10:00:00.000000Z",
        )
        self.assertEqual(
            record.state,
            attempt.EXECUTION_ATTEMPT_STATE_ATTEMPTING,
        )
        self.assertFalse(record.execution_started_proven)
        self.assertFalse(record.execution_returned)
        self.assertFalse(record.sanitization_verified)
        self.assertFalse(record.automatic_replay_allowed)
        self.assertTrue(record.requires_manual_review_if_interrupted)
        self.assertTrue(attempt._record_integrity_valid(record))

    def test_store_persists_private_fsynced_attempting_record(self):
        root = self.private_dir()
        store = attempt.DurableExecutionAttemptJournal(
            root / "attempts.json"
        )
        auth = authorization_record()
        record = attempt._build_record(
            authorization=auth,
            attempt_id="xeattempt_" + ("6" * 64),
            attempted_at_utc="2026-09-02T10:00:00.000000Z",
        )

        lock_fd = store._open_lock()
        try:
            store._write_locked([record])
            persisted = store._read_locked()
        finally:
            store._close_lock(lock_fd)

        self.assertEqual(persisted, [record])
        self.assertEqual(
            stat.S_IMODE(store.path.stat().st_mode),
            0o600,
        )

    def test_store_duplicate_authorization_is_refused(self):
        root = self.private_dir()
        store = attempt.DurableExecutionAttemptJournal(
            root / "attempts.json"
        )
        auth = authorization_record()
        first = attempt._build_record(
            authorization=auth,
            attempt_id="xeattempt_" + ("7" * 64),
            attempted_at_utc="2026-09-02T10:00:00.000000Z",
        )
        second = attempt._build_record(
            authorization=auth,
            attempt_id="xeattempt_" + ("8" * 64),
            attempted_at_utc="2026-09-02T10:01:00.000000Z",
        )

        lock_fd = store._open_lock()
        try:
            with self.assertRaises(attempt.ExecutionAttemptError):
                store._write_locked([first, second])
        finally:
            store._close_lock(lock_fd)

    def test_store_tamper_is_refused(self):
        root = self.private_dir()
        store = attempt.DurableExecutionAttemptJournal(
            root / "attempts.json"
        )
        auth = authorization_record()
        record = attempt._build_record(
            authorization=auth,
            attempt_id="xeattempt_" + ("9" * 64),
            attempted_at_utc="2026-09-02T10:00:00.000000Z",
        )
        lock_fd = store._open_lock()
        try:
            store._write_locked([record])
        finally:
            store._close_lock(lock_fd)

        doc = json.loads(store.path.read_text(encoding="utf-8"))
        doc["entries"][0]["operation"] = "tampered"
        store.path.write_text(
            json.dumps(doc) + "\n",
            encoding="utf-8",
        )
        os.chmod(store.path, 0o600)

        lock_fd = store._open_lock()
        try:
            with self.assertRaises(attempt.ExecutionAttemptError):
                store._read_locked()
        finally:
            store._close_lock(lock_fd)

    def test_store_rejects_nonprivate_parent(self):
        root = self.private_dir()
        os.chmod(root, 0o755)
        store = attempt.DurableExecutionAttemptJournal(
            root / "attempts.json"
        )
        with self.assertRaises(attempt.ExecutionAttemptError):
            store._open_lock()

    def test_inactive_capability_restart_state_is_refused(self):
        self.start_fake_patches()
        events = []
        capability = FakeCapability(
            authorization_record(),
            events,
        )
        capability.active = False
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )
        with self.assertRaises(attempt.ExecutionAttemptError):
            attempt.record_execution_attempt(
                store=store,
                capability=capability,
            )
        self.assertFalse(store.path.exists())

    def test_wrong_capability_type_is_refused(self):
        store = attempt.DurableExecutionAttemptJournal(
            self.private_dir() / "attempts.json"
        )
        with self.assertRaises(attempt.ExecutionAttemptError):
            attempt.record_execution_attempt(
                store=store,
                capability=object(),
            )

    def test_non_reserved_authorization_is_refused_before_persist(self):
        self.start_fake_patches()
        auth = authorization_record()
        auth = replace(auth, state="AUTHORIZED")
        events = []
        capability = FakeCapability(auth, events)
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )
        with self.assertRaises(attempt.ExecutionAttemptError):
            attempt.record_execution_attempt(
                store=store,
                capability=capability,
            )
        self.assertNotIn("persist", events)

    def test_identity_mismatch_is_refused_before_persist(self):
        self.start_fake_patches()
        events = []
        capability = FakeCapability(
            authorization_record(),
            events,
        )
        capability._identity = (
            IDENTITY[0],
            IDENTITY[1],
            "8:1",
            IDENTITY[3],
        )
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )
        with self.assertRaises(attempt.ExecutionAttemptError):
            attempt.record_execution_attempt(
                store=store,
                capability=capability,
            )
        self.assertNotIn("persist", events)

    def test_final_descriptor_mismatch_refuses_before_persist(self):
        self.start_fake_patches()
        events = []
        capability = FakeCapability(
            authorization_record(),
            events,
        )
        capability._lease_scope._claim_scope.revalidate_descriptor = (
            lambda: "8:1"
        )
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )
        with self.assertRaises(attempt.ExecutionAttemptError):
            attempt.record_execution_attempt(
                store=store,
                capability=capability,
            )
        self.assertNotIn("persist", events)

    def test_fresh_safety_failure_refuses_before_persist(self):
        self.start_fake_patches()
        events = []
        capability = FakeCapability(
            authorization_record(),
            events,
        )
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )
        with patch.object(
            attempt.leases,
            "_fresh_safety_cycle",
            side_effect=RuntimeError("synthetic safety failure"),
        ):
            with self.assertRaises(attempt.ExecutionAttemptError):
                attempt.record_execution_attempt(
                    store=store,
                    capability=capability,
                )
        self.assertNotIn("persist", events)
        self.assertIn("attempt-unlock", events)

    def test_final_integrity_failure_refuses_before_persist(self):
        self.start_fake_patches()
        events = []
        capability = FakeCapability(
            authorization_record(),
            events,
        )
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )
        with patch.object(
            attempt.leases,
            "_internal_integrity_binding_valid",
            side_effect=[True, False],
        ):
            with self.assertRaises(attempt.ExecutionAttemptError):
                attempt.record_execution_attempt(
                    store=store,
                    capability=capability,
                )
        self.assertNotIn("persist", events)

    def test_authorization_change_during_validation_refuses(self):
        self.start_fake_patches()
        events = []
        auth = authorization_record()
        capability = FakeCapability(auth, events)
        changed = replace(
            auth,
            request_id="changed-request",
        )

        reads = {"count": 0}

        class ChangingScope(FakeAuthorizationScope):
            @property
            def record(self):
                self.events.append("authorization")
                reads["count"] += 1
                return auth if reads["count"] == 1 else changed

        capability._authorization_scope = ChangingScope(
            auth,
            events,
        )
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )

        with self.assertRaises(attempt.ExecutionAttemptError):
            attempt.record_execution_attempt(
                store=store,
                capability=capability,
            )
        self.assertNotIn("persist", events)

    def test_attempt_lock_is_acquired_before_final_safety_and_persist(self):
        self.start_fake_patches()
        events = []
        capability = FakeCapability(
            authorization_record(),
            events,
        )
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )

        def fresh(**kwargs):
            events.append("fresh-safety")
            return ("before", "after")

        with patch.object(
            attempt.leases,
            "_fresh_safety_cycle",
            side_effect=fresh,
        ):
            record = attempt.record_execution_attempt(
                store=store,
                capability=capability,
            )

        self.assertEqual(
            record.state,
            attempt.EXECUTION_ATTEMPT_STATE_ATTEMPTING,
        )
        self.assertLess(
            events.index("attempt-lock"),
            events.index("fresh-safety"),
        )
        self.assertLess(
            events.index("fresh-safety"),
            events.index("persist"),
        )
        self.assertLess(
            events.index("persist"),
            events.index("attempt-unlock"),
        )

    def test_success_binds_exact_reserved_provenance(self):
        self.start_fake_patches()
        events = []
        auth = authorization_record()
        capability = FakeCapability(auth, events)
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )

        with patch.object(
            attempt.leases,
            "_fresh_safety_cycle",
            return_value=("before", "after"),
        ):
            record = attempt.record_execution_attempt(
                store=store,
                capability=capability,
            )

        self.assertEqual(record.authorization_id, auth.authorization_id)
        self.assertEqual(record.lease_binding_id, auth.lease_binding_id)
        self.assertEqual(record.handoff_id, auth.handoff_id)
        self.assertEqual(record.target_path, auth.target_path)
        self.assertEqual(
            record.target_major_minor,
            auth.target_major_minor,
        )
        self.assertEqual(
            record.target_binding_hash,
            auth.target_binding_hash,
        )
        self.assertEqual(record.gate_id, auth.gate_id)
        self.assertEqual(record.binding_id, auth.binding_id)
        self.assertEqual(
            record.journal_entry_hash,
            auth.journal_entry_hash,
        )
        self.assertEqual(record.request_hash, auth.request_hash)
        self.assertEqual(
            record.record_snapshot_hash,
            auth.record_snapshot_hash,
        )
        self.assertEqual(record.operation, auth.operation)

    def test_replay_is_refused_after_durable_attempt(self):
        self.start_fake_patches()
        events = []
        capability = FakeCapability(
            authorization_record(),
            events,
        )
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )

        with patch.object(
            attempt.leases,
            "_fresh_safety_cycle",
            return_value=("before", "after"),
        ):
            first = attempt.record_execution_attempt(
                store=store,
                capability=capability,
            )
            with self.assertRaisesRegex(
                attempt.ExecutionAttemptError,
                "automatic replay is refused",
            ):
                attempt.record_execution_attempt(
                    store=store,
                    capability=capability,
                )

        persisted = store.entry_for_authorization(AUTH_ID)
        self.assertEqual(persisted, first)
        self.assertFalse(persisted.automatic_replay_allowed)

    def test_concurrent_duplicate_attempt_allows_exactly_one(self):
        self.start_fake_patches()
        events = []
        capability = FakeCapability(
            authorization_record(),
            events,
        )
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )
        barrier = threading.Barrier(2)
        outcomes = []
        guard = threading.Lock()

        def worker():
            barrier.wait()
            try:
                attempt.record_execution_attempt(
                    store=store,
                    capability=capability,
                )
                result = "success"
            except attempt.ExecutionAttemptError:
                result = "refused"
            with guard:
                outcomes.append(result)

        threads = [
            threading.Thread(target=worker)
            for _ in range(2)
        ]
        with patch.object(
            attempt.leases,
            "_fresh_safety_cycle",
            return_value=("before", "after"),
        ):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(outcomes.count("success"), 1)
        self.assertEqual(outcomes.count("refused"), 1)

    def test_attempt_store_lock_releases_on_write_failure(self):
        self.start_fake_patches()
        events = []
        capability = FakeCapability(
            authorization_record(),
            events,
        )

        class FailingStore(TrackingStore):
            def _write_locked(self, entries):
                self.events.append("persist-failure")
                raise attempt.ExecutionAttemptError(
                    "synthetic persistence failure"
                )

        store = FailingStore(
            self.private_dir() / "attempts.json",
            events,
        )

        with patch.object(
            attempt.leases,
            "_fresh_safety_cycle",
            return_value=("before", "after"),
        ), patch.object(
            attempt,
            "_STORE_TYPE",
            FailingStore,
        ):
            with self.assertRaises(attempt.ExecutionAttemptError):
                attempt.record_execution_attempt(
                    store=store,
                    capability=capability,
                )

        self.assertIn("attempt-unlock", events)
        self.assertFalse(store.path.exists())

    def test_source_has_no_target_open_device_io_command_or_executor_surface(self):
        source = Path(attempt.__file__).read_text(encoding="utf-8")

        for forbidden in (
            "subprocess",
            "Popen",
            "os.system",
            "wipefs",
            "mkfs",
            "shred",
            "losetup",
            "def execute(",
            "def write_target(",
            "def device_operation(",
        ):
            self.assertNotIn(forbidden, source)

        self.assertNotIn("os.pwrite(", source)
        self.assertNotIn("os.lseek(", source)
        self.assertNotIn("target_path, flags", source)
        self.assertNotIn("capability.target_path", source)

    def test_source_defines_no_success_completion_or_result_transition(self):
        source = Path(attempt.__file__).read_text(encoding="utf-8")
        self.assertIn(
            'EXECUTION_ATTEMPT_STATE_ATTEMPTING = "ATTEMPTING"',
            source,
        )
        self.assertNotIn("STATE_COMPLETED", source)
        self.assertNotIn("STATE_SUCCESS", source)
        self.assertNotIn("STATE_SANITIZED", source)
        self.assertNotIn("mark_completed", source)
        self.assertNotIn("mark_success", source)
        self.assertNotIn("rollback_attempt", source)


if __name__ == "__main__":
    unittest.main()
