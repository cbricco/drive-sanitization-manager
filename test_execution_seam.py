from __future__ import annotations

from dataclasses import replace
import copy
import inspect
import os
from pathlib import Path
import pickle
import tempfile
import unittest
from unittest.mock import patch

import execution_attempt_journal as attempt
import execution_seam as seam
import executor_authorization as exauth


IDENTITY = (
    "xhnd_" + ("a" * 64),
    "/synthetic/b3fe",
    "8:0",
    "sha256:" + ("b" * 64),
)
XELI = "xeli_" + ("c" * 64)
AUTH_ID = "xeauth_" + ("d" * 64)
FD = 91


def authorization_record(**changes):
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
        journal_state=exauth._COMPLETED_JOURNAL_STATE,
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
    base = replace(base, **changes)
    return replace(
        base,
        record_hash=exauth._canonical_hash(
            exauth._record_payload(base)
        ),
    )


def attempt_record(auth=None, *, token="4"):
    if auth is None:
        auth = authorization_record()
    return attempt._build_record(
        authorization=auth,
        attempt_id="xeattempt_" + (token * 64),
        attempted_at_utc="2026-09-02T10:00:00.000000Z",
    )


class FakeHeldReference:
    pass


class FakeClaimScope:
    def __init__(self, events, *, fd=FD):
        self._entered = True
        self.events = events
        self.identity = IDENTITY
        self.held = FakeHeldReference()
        self.fd = fd

    def _state_locked(self):
        self.events.append("claim-state")
        return (
            self.held,
            IDENTITY,
            "pre-continuity",
            "post-continuity",
            self.fd,
        )

    def revalidate_descriptor(self):
        self.events.append("descriptor")
        return IDENTITY[2]


class ChangingFdClaimScope(FakeClaimScope):
    def __init__(self, events):
        super().__init__(events)
        self.calls = 0

    def _state_locked(self):
        self.calls += 1
        value = super()._state_locked()
        if self.calls >= 2:
            return (*value[:-1], FD + 1)
        return value


class FakeLease:
    def __init__(self):
        self._consumed = True
        self._arguments = {}
        self._handoff_id = IDENTITY[0]
        self._target_path = IDENTITY[1]
        self._target_major_minor = IDENTITY[2]
        self._target_binding_hash = IDENTITY[3]
        self.absolute_write_exclusion_guaranteed = False
        self.ordinary_raw_writers_excluded = False
        self.execution_supported = False
        self.executor_eligible = False
        self.execution_authorized = False
        self.internal_integrity_binding_only = True
        self.external_authorization_proven = False


class FakeLeaseScope:
    def __init__(self, claim_scope):
        self._entered = True
        self._claim_scope = claim_scope


class FakeAuthorizationScope:
    def __init__(self, record, events, *, alternate=None):
        self._entered = True
        self.current_record = record
        self.alternate = alternate
        self.events = events
        self.reads = 0

    @property
    def record(self):
        self.reads += 1
        self.events.append("authorization")
        if self.alternate is not None and self.reads >= 2:
            return self.alternate
        return self.current_record


class FakeCapability:
    def __init__(
        self,
        auth_record,
        events,
        *,
        claim_scope=None,
        alternate_authorization=None,
    ):
        if claim_scope is None:
            claim_scope = FakeClaimScope(events)
        self._lease = FakeLease()
        self._lease_scope = FakeLeaseScope(claim_scope)
        self._authorization_scope = FakeAuthorizationScope(
            auth_record,
            events,
            alternate=alternate_authorization,
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

    def _read_locked(self):
        self.events.append("attempt-read")
        return super()._read_locked()

    def _write_locked(self, entries):
        self.events.append("attempt-write")
        return super()._write_locked(entries)

    def _close_lock(self, fd):
        self.events.append("attempt-unlock")
        return super()._close_lock(fd)


class ChangingReadStore(TrackingStore):
    def __init__(self, path, events, replacement):
        super().__init__(path, events)
        self.read_count = 0
        self.replacement = replacement

    def _read_locked(self):
        result = super()._read_locked()
        self.read_count += 1
        if self.read_count >= 2:
            return [self.replacement]
        return result


class ExecutionSeamTests(unittest.TestCase):
    def private_dir(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        os.chmod(temp.name, 0o700)
        return Path(temp.name)

    def make_store(self, record, events, store_type=TrackingStore):
        store = store_type(
            self.private_dir() / "attempts.json",
            events,
        )
        lock_fd = store._open_lock()
        try:
            store._write_locked([record])
        finally:
            store._close_lock(lock_fd)
        events.clear()
        return store

    def fake_patches(self, capability, store_type=TrackingStore):
        claim_type = type(
            capability._lease_scope._claim_scope
        )
        return (
            patch.object(
                attempt,
                "_CAPABILITY_TYPE",
                FakeCapability,
            ),
            patch.object(attempt, "_LEASE_TYPE", FakeLease),
            patch.object(
                attempt,
                "_LEASE_SCOPE_TYPE",
                FakeLeaseScope,
            ),
            patch.object(
                attempt,
                "_AUTH_SCOPE_TYPE",
                FakeAuthorizationScope,
            ),
            patch.object(
                attempt,
                "_CLAIM_SCOPE_TYPE",
                claim_type,
            ),
            patch.object(
                attempt.leases,
                "_internal_integrity_binding_valid",
                return_value=True,
            ),
            patch.object(
                seam,
                "_STORE_TYPE",
                store_type,
            ),
            patch.object(
                attempt.leases,
                "_fresh_safety_cycle",
                side_effect=lambda **kwargs: capability
                ._lease_scope
                ._claim_scope
                .events.append("safety"),
            ),
        )

    def start_patches(self, capability, store_type=TrackingStore):
        for manager in self.fake_patches(
            capability,
            store_type=store_type,
        ):
            manager.start()
            self.addCleanup(manager.stop)

    def test_successful_private_descriptor_seam(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        scope = seam._locked_execution_seam_scope(
            store=store,
            capability=capability,
            attempt_record=record,
        )
        with scope:
            self.assertEqual(scope._descriptor_locked(), FD)

        self.assertIn("attempt-lock", events)
        self.assertIn("safety", events)
        self.assertIn("descriptor", events)
        self.assertEqual(events[-1], "attempt-unlock")

    def test_descriptor_bridge_is_single_use(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        with seam._locked_execution_seam_scope(
            store=store,
            capability=capability,
            attempt_record=record,
        ) as scope:
            self.assertEqual(scope._descriptor_locked(), FD)
            with self.assertRaises(seam.ExecutionSeamError):
                scope._descriptor_locked()

    def test_scope_is_single_use(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        scope = seam._locked_execution_seam_scope(
            store=store,
            capability=capability,
            attempt_record=record,
        )
        with scope:
            pass
        with self.assertRaises(seam.ExecutionSeamError):
            scope.__enter__()

    def test_scope_is_noncopyable_and_nonserializable(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        scope = seam._locked_execution_seam_scope(
            store=store,
            capability=capability,
            attempt_record=record,
        )
        with self.assertRaises(seam.ExecutionSeamError):
            copy.copy(scope)
        with self.assertRaises(seam.ExecutionSeamError):
            copy.deepcopy(scope)
        with self.assertRaises(seam.ExecutionSeamError):
            pickle.dumps(scope)

    def test_wrong_store_exact_type_is_refused(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = attempt.DurableExecutionAttemptJournal(
            self.private_dir() / "attempts.json"
        )
        self.start_patches(capability)
        with self.assertRaises(seam.ExecutionSeamError):
            seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=record,
            )

    def test_wrong_attempt_record_type_is_refused(self):
        events = []
        auth = authorization_record()
        capability = FakeCapability(auth, events)
        store = TrackingStore(
            self.private_dir() / "attempts.json",
            events,
        )
        self.start_patches(capability)
        with self.assertRaises(seam.ExecutionSeamError):
            seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=object(),
            )

    def test_inactive_capability_restart_state_is_refused(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        capability.active = False
        store = self.make_store(record, events)
        self.start_patches(capability)

        with self.assertRaises(attempt.ExecutionAttemptError):
            with seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=record,
            ):
                pass
        self.assertNotIn("attempt-lock", events)

    def test_b3fa_exclusion_claims_remain_conservative(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        capability._lease.ordinary_raw_writers_excluded = True
        store = self.make_store(record, events)
        self.start_patches(capability)

        with self.assertRaises(seam.ExecutionSeamError):
            with seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=record,
            ):
                pass
        self.assertNotIn("attempt-lock", events)

    def test_unpersisted_attempt_is_refused(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        other = attempt_record(auth, token="5")
        capability = FakeCapability(auth, events)
        store = self.make_store(other, events)
        self.start_patches(capability)

        with self.assertRaises(seam.ExecutionSeamError):
            with seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=record,
            ):
                pass
        self.assertEqual(events[-1], "attempt-unlock")

    def test_tampered_attempt_is_refused(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        tampered = replace(record, operation="tampered")
        with self.assertRaises(seam.ExecutionSeamError):
            seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=tampered,
            )

    def test_authorization_provenance_mismatch_is_refused(self):
        events = []
        auth = authorization_record()
        other_auth = authorization_record(
            request_id="other-request"
        )
        record = attempt_record(other_auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        with self.assertRaises(seam.ExecutionSeamError):
            with seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=record,
            ):
                pass
        self.assertEqual(events[-1], "attempt-unlock")

    def test_noncompleted_gate_journal_provenance_is_refused(self):
        events = []
        auth = authorization_record(
            journal_state="not-completed"
        )
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        with self.assertRaises(seam.ExecutionSeamError):
            with seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=record,
            ):
                pass
        self.assertEqual(events[-1], "attempt-unlock")

    def test_final_safety_failure_releases_attempt_lock(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        with patch.object(
            seam.attempt,
            "_final_pinned_safety_cycle",
            side_effect=RuntimeError("synthetic-safety-failure"),
        ):
            with self.assertRaises(RuntimeError):
                with seam._locked_execution_seam_scope(
                    store=store,
                    capability=capability,
                    attempt_record=record,
                ):
                    pass

        self.assertEqual(events[-1], "attempt-unlock")

    def test_descriptor_stability_change_is_refused(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        claim = ChangingFdClaimScope(events)
        capability = FakeCapability(
            auth,
            events,
            claim_scope=claim,
        )
        store = self.make_store(record, events)
        self.start_patches(capability)

        with self.assertRaises(seam.ExecutionSeamError):
            with seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=record,
            ):
                pass
        self.assertEqual(events[-1], "attempt-unlock")

    def test_attempt_reread_change_is_refused(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        replacement = attempt_record(auth, token="6")
        capability = FakeCapability(auth, events)

        class Store(ChangingReadStore):
            def __init__(self, path, event_list):
                super().__init__(
                    path,
                    event_list,
                    replacement,
                )

        store = self.make_store(
            record,
            events,
            store_type=Store,
        )
        self.start_patches(capability, store_type=Store)

        with self.assertRaises(seam.ExecutionSeamError):
            with seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=record,
            ):
                pass
        self.assertEqual(events[-1], "attempt-unlock")

    def test_authorization_change_after_safety_is_refused(self):
        events = []
        auth = authorization_record()
        alternate = authorization_record(
            request_id="changed-after-safety"
        )
        record = attempt_record(auth)
        capability = FakeCapability(
            auth,
            events,
            alternate_authorization=alternate,
        )
        store = self.make_store(record, events)
        self.start_patches(capability)

        with self.assertRaises(seam.ExecutionSeamError):
            with seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=record,
            ):
                pass
        self.assertEqual(events[-1], "attempt-unlock")

    def test_seam_never_writes_attempt_journal(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        with seam._locked_execution_seam_scope(
            store=store,
            capability=capability,
            attempt_record=record,
        ):
            pass

        self.assertNotIn("attempt-write", events)

    def test_no_public_descriptor_or_executor_surface(self):
        public = {
            name
            for name in dir(seam._LockedExecutionSeamScope)
            if not name.startswith("_")
        }
        forbidden = {
            "fd",
            "fileno",
            "read",
            "write",
            "seek",
            "callback",
            "command",
            "subprocess",
            "execute",
            "executor",
            "device_operation",
            "descriptor",
        }
        self.assertTrue(public.isdisjoint(forbidden))
        self.assertNotIn(
            "_LockedExecutionSeamScope",
            seam.__all__,
        )
        self.assertNotIn(
            "_locked_execution_seam_scope",
            seam.__all__,
        )

    def test_source_has_no_device_io_command_or_path_open_surface(self):
        source = inspect.getsource(seam)
        forbidden = (
            "os.pwrite",
            "os.write",
            "os.read",
            "os.lseek",
            "os.open",
            "open(",
            "subprocess",
            "Popen",
            "wipefs",
            "shred",
            "losetup",
            "def execute",
            "def executor",
            "device_operation",
        )
        for marker in forbidden:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, source)

    def test_attempt_lock_is_last_and_released_after_safety(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        with seam._locked_execution_seam_scope(
            store=store,
            capability=capability,
            attempt_record=record,
        ) as scope:
            scope._descriptor_locked()

        lock_at = events.index("attempt-lock")
        safety_at = events.index("safety")
        unlock_at = len(events) - 1
        self.assertLess(lock_at, safety_at)
        self.assertEqual(events[unlock_at], "attempt-unlock")

    def test_exception_inside_scope_releases_attempt_lock(self):
        events = []
        auth = authorization_record()
        record = attempt_record(auth)
        capability = FakeCapability(auth, events)
        store = self.make_store(record, events)
        self.start_patches(capability)

        with self.assertRaisesRegex(
            RuntimeError,
            "synthetic-body-failure",
        ):
            with seam._locked_execution_seam_scope(
                store=store,
                capability=capability,
                attempt_record=record,
            ):
                raise RuntimeError("synthetic-body-failure")

        self.assertEqual(events[-1], "attempt-unlock")


if __name__ == "__main__":
    unittest.main()
