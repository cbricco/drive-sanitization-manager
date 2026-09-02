from __future__ import annotations

import ast
import copy
from pathlib import Path
import pickle
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import execution_lease as leases
import executor_authorization as exauth
import executor_ready_capability as ready


IDENTITY = (
    "xhnd_" + ("a" * 64),
    "/synthetic/b3fc",
    "8:0",
    "sha256:" + ("b" * 64),
)
XELI = "xeli_" + ("c" * 64)
AUTHORIZATION_ID = "xeauth_" + ("d" * 64)


def provenance():
    return {
        "handoff_id": IDENTITY[0],
        "gate_id": "xgate_" + ("e" * 64),
        "binding_id": "xeb_" + ("f" * 64),
        "journal_policy_version": "journal-policy",
        "journal_schema_version": 1,
        "journal_state": "completed",
        "journal_entry_hash": "sha256:" + ("1" * 64),
        "approval_id": "approval-synthetic",
        "request_id": "request-synthetic",
        "request_hash": "sha256:" + ("2" * 64),
        "record_snapshot_hash": "sha256:" + ("3" * 64),
        "internal_record_id": "record-synthetic",
        "method_profile_id": "synthetic-method",
        "operation": "sanitize",
        "handoff_target_binding_hash": IDENTITY[3],
    }


def record(state=exauth.EXECUTOR_AUTHORIZATION_STATE_RESERVED):
    p = provenance()
    return exauth.ExecutorAuthorizationRecord(
        authorization_id=AUTHORIZATION_ID,
        policy_version=exauth.EXECUTOR_AUTHORIZATION_POLICY_VERSION,
        schema_version=exauth.EXECUTOR_AUTHORIZATION_SCHEMA_VERSION,
        state=state,
        lease_binding_id=XELI,
        handoff_id=IDENTITY[0],
        target_path=IDENTITY[1],
        target_major_minor=IDENTITY[2],
        target_binding_hash=IDENTITY[3],
        gate_id=p["gate_id"],
        binding_id=p["binding_id"],
        journal_policy_version=p["journal_policy_version"],
        journal_schema_version=p["journal_schema_version"],
        journal_state=p["journal_state"],
        journal_entry_hash=p["journal_entry_hash"],
        approval_id=p["approval_id"],
        request_id=p["request_id"],
        request_hash=p["request_hash"],
        record_snapshot_hash=p["record_snapshot_hash"],
        internal_record_id=p["internal_record_id"],
        method_profile_id=p["method_profile_id"],
        operation=p["operation"],
        authorized_at_utc="2026-08-28T10:00:00.000000Z",
        reserved_at_utc=(
            "2026-08-28T10:01:00.000000Z"
            if state == exauth.EXECUTOR_AUTHORIZATION_STATE_RESERVED
            else None
        ),
        record_hash="synthetic-test-record-hash",
    )


class FakeClaimScope:
    def __init__(self):
        self.revalidations = 0

    def revalidate_descriptor(self):
        self.revalidations += 1
        return IDENTITY[2]


class FakeLease:
    def __init__(self):
        self._arguments = {}
        self._consumed = False


class FakeStore:
    pass


class FakeLeaseScope:
    def __init__(self, lease, events, *, fail_consume=False):
        self.lease = lease
        self.events = events
        self.fail_consume = fail_consume
        self.entered = False

    def __enter__(self):
        self.events.append("lease-enter")
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.events.append("lease-exit")
        self.entered = False
        return False

    @property
    def identity(self):
        if not self.entered:
            raise RuntimeError("lease scope inactive")
        return IDENTITY

    @property
    def execution_authorization_integrity_binding_id(self):
        if not self.entered:
            raise RuntimeError("lease scope inactive")
        return XELI

    def _consume_locked_for_executor_ready(self):
        self.events.append("lease-consume")
        if self.fail_consume:
            raise leases.ExecutionLeaseError("synthetic final consume failure")
        self.lease._consumed = True
        return IDENTITY, XELI


class FakeAuthorizationScope:
    def __init__(self, events, current_record, *, fail_enter=False):
        self.events = events
        self.current_record = current_record
        self.fail_enter = fail_enter
        self.entered = False

    def __enter__(self):
        self.events.append("auth-enter")
        if self.fail_enter:
            raise exauth.ExecutorAuthorizationError(
                "synthetic reserved-scope failure"
            )
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.events.append("auth-exit")
        self.entered = False
        return False

    @property
    def record(self):
        if not self.entered:
            raise RuntimeError("authorization scope inactive")
        return self.current_record


class FakeAuthStoreForPrivateScope:
    def __init__(self, entries):
        self.entries = list(entries)
        self.opened = 0
        self.closed = 0

    def _open_lock(self):
        self.opened += 1
        return 71

    def _close_lock(self, fd):
        if fd != 71:
            raise AssertionError("unexpected lock fd")
        self.closed += 1

    def _read_locked(self):
        return list(self.entries)


class ExecutorReadyCapabilityTests(unittest.TestCase):
    def setUp(self):
        exauth._LIVE_AUTHORIZATIONS.clear()

    def test_locked_lease_consume_source_never_reacquires_state_lock(self):
        source = Path(leases.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        target = None
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.FunctionDef)
                and node.name == "_consume_locked_for_executor_ready"
            ):
                target = ast.get_source_segment(source, node)
                break

        self.assertIsNotNone(target)
        self.assertNotIn("_state_lock.acquire", target)
        self.assertNotIn("with self._lease._state_lock", target)
        self.assertGreaterEqual(target.count("revalidate_descriptor"), 2)
        self.assertIn("_fresh_safety_cycle", target)
        self.assertIn("execution_lease._consumed = True", target)

    def test_locked_lease_consume_calls_final_checks_then_consumes(self):
        scope = object.__new__(
            leases._LockedExecutionLeaseValidationScope
        )
        scope._lease = FakeLease()
        scope._claim_scope = FakeClaimScope()
        scope._entered = True
        scope._used = True
        scope._entry_lock = threading.Lock()

        with patch.object(
            leases._LockedExecutionLeaseValidationScope,
            "_state_locked",
            side_effect=[
                (IDENTITY, XELI),
                (IDENTITY, XELI),
            ],
        ), patch.object(
            leases,
            "_fresh_safety_cycle",
            return_value=("hsc_" + ("1" * 64), "hsc_" + ("2" * 64)),
        ) as fresh, patch.object(
            leases,
            "_internal_integrity_binding_valid",
            return_value=True,
        ):
            result = scope._consume_locked_for_executor_ready()

        self.assertEqual(result, (IDENTITY, XELI))
        self.assertTrue(scope._lease._consumed)
        self.assertEqual(scope._claim_scope.revalidations, 2)
        self.assertEqual(fresh.call_count, 1)

    def test_locked_lease_consume_failure_does_not_consume(self):
        scope = object.__new__(
            leases._LockedExecutionLeaseValidationScope
        )
        scope._lease = FakeLease()
        scope._claim_scope = FakeClaimScope()
        scope._entered = True
        scope._used = True
        scope._entry_lock = threading.Lock()

        with patch.object(
            leases._LockedExecutionLeaseValidationScope,
            "_state_locked",
            return_value=(IDENTITY, XELI),
        ), patch.object(
            leases,
            "_fresh_safety_cycle",
            side_effect=RuntimeError("synthetic final safety failure"),
        ):
            with self.assertRaises(leases.ExecutionLeaseError):
                scope._consume_locked_for_executor_ready()

        self.assertFalse(scope._lease._consumed)

    def test_reserved_scope_holds_exact_reserved_record_and_store_lock(self):
        lease = FakeLease()
        current = record()
        store = FakeAuthStoreForPrivateScope([current])

        with patch.object(exauth, "_LEASE_TYPE", FakeLease), patch.object(
            exauth,
            "DurableExecutorAuthorizationStore",
            FakeAuthStoreForPrivateScope,
        ), patch.object(
            exauth,
            "_record_integrity_valid",
            return_value=True,
        ):
            exauth._LIVE_AUTHORIZATIONS[AUTHORIZATION_ID] = lease
            scope = exauth._locked_reserved_executor_authorization_scope(
                store=store,
                authorization_id=AUTHORIZATION_ID,
                lease=lease,
                lease_binding_id=XELI,
                identity=IDENTITY,
            )
            with scope:
                self.assertIs(scope.record, current)
                self.assertEqual(store.opened, 1)
                self.assertEqual(store.closed, 0)

        self.assertEqual(store.closed, 1)

    def test_reserved_scope_rejects_non_reserved_record(self):
        lease = FakeLease()
        current = record(
            exauth.EXECUTOR_AUTHORIZATION_STATE_AUTHORIZED
        )
        store = FakeAuthStoreForPrivateScope([current])

        with patch.object(exauth, "_LEASE_TYPE", FakeLease), patch.object(
            exauth,
            "DurableExecutorAuthorizationStore",
            FakeAuthStoreForPrivateScope,
        ), patch.object(
            exauth,
            "_record_integrity_valid",
            return_value=True,
        ):
            exauth._LIVE_AUTHORIZATIONS[AUTHORIZATION_ID] = lease
            scope = exauth._locked_reserved_executor_authorization_scope(
                store=store,
                authorization_id=AUTHORIZATION_ID,
                lease=lease,
                lease_binding_id=XELI,
                identity=IDENTITY,
            )
            with self.assertRaises(exauth.ExecutorAuthorizationError):
                with scope:
                    self.fail("AUTHORIZED record unexpectedly accepted")

        self.assertEqual(store.closed, 1)

    def test_reserved_scope_rejects_restart_latch_loss(self):
        lease = FakeLease()
        current = record()
        store = FakeAuthStoreForPrivateScope([current])

        with patch.object(exauth, "_LEASE_TYPE", FakeLease), patch.object(
            exauth,
            "DurableExecutorAuthorizationStore",
            FakeAuthStoreForPrivateScope,
        ), patch.object(
            exauth,
            "_record_integrity_valid",
            return_value=True,
        ):
            scope = exauth._locked_reserved_executor_authorization_scope(
                store=store,
                authorization_id=AUTHORIZATION_ID,
                lease=lease,
                lease_binding_id=XELI,
                identity=IDENTITY,
            )
            with self.assertRaisesRegex(
                exauth.ExecutorAuthorizationError,
                "live-lease latch",
            ):
                with scope:
                    self.fail("restart-lost latch unexpectedly accepted")

    def test_reserved_scope_is_single_use(self):
        lease = FakeLease()
        current = record()
        store = FakeAuthStoreForPrivateScope([current])

        with patch.object(exauth, "_LEASE_TYPE", FakeLease), patch.object(
            exauth,
            "DurableExecutorAuthorizationStore",
            FakeAuthStoreForPrivateScope,
        ), patch.object(
            exauth,
            "_record_integrity_valid",
            return_value=True,
        ):
            exauth._LIVE_AUTHORIZATIONS[AUTHORIZATION_ID] = lease
            scope = exauth._locked_reserved_executor_authorization_scope(
                store=store,
                authorization_id=AUTHORIZATION_ID,
                lease=lease,
                lease_binding_id=XELI,
                identity=IDENTITY,
            )
            with scope:
                pass
            with self.assertRaisesRegex(
                exauth.ExecutorAuthorizationError,
                "single-use",
            ):
                scope.__enter__()

    def capability_environment(
        self,
        *,
        fail_auth_enter=False,
        fail_consume=False,
        current_record=None,
        provenance_value=None,
    ):
        events = []
        lease = FakeLease()
        store = FakeStore()
        current_record = current_record or record()
        provenance_value = provenance_value or provenance()

        return SimpleNamespace(
            events=events,
            lease=lease,
            store=store,
            lease_scope=FakeLeaseScope(
                lease,
                events,
                fail_consume=fail_consume,
            ),
            auth_scope=FakeAuthorizationScope(
                events,
                current_record,
                fail_enter=fail_auth_enter,
            ),
            current_record=current_record,
            provenance_value=provenance_value,
        )

    def enter_with_patches(self, env):
        managers = (
            patch.object(ready, "_LEASE_TYPE", FakeLease),
            patch.object(ready, "_STORE_TYPE", FakeStore),
            patch.object(
                ready,
                "_LEASE_SCOPE_FACTORY",
                return_value=env.lease_scope,
            ),
            patch.object(
                ready,
                "_RESERVED_SCOPE_FACTORY",
                return_value=env.auth_scope,
            ),
            patch.object(
                ready,
                "_HANDOFF_PROVENANCE",
                return_value=env.provenance_value,
            ),
        )
        for manager in managers:
            manager.start()
            self.addCleanup(manager.stop)

        return ready.prepare_executor_ready_capability(
            lease=env.lease,
            store=env.store,
            authorization_id=AUTHORIZATION_ID,
            handoff=object(),
            journal=object(),
        )

    def test_capability_enters_lock_order_and_consumes_before_return(self):
        env = self.capability_environment()
        capability = self.enter_with_patches(env)

        with capability as active:
            self.assertIs(active, capability)
            self.assertTrue(env.lease._consumed)
            self.assertTrue(capability.lease_consumed)
            self.assertTrue(capability.active)
            self.assertEqual(
                env.events,
                ["lease-enter", "auth-enter", "lease-consume"],
            )
            self.assertFalse(capability.execution_authorized)
            self.assertFalse(capability.execution_supported)
            self.assertFalse(capability.executor_eligible)
            self.assertFalse(capability.execution_performed)
            self.assertTrue(capability.requires_future_executor)

        self.assertEqual(
            env.events,
            [
                "lease-enter",
                "auth-enter",
                "lease-consume",
                "auth-exit",
                "lease-exit",
            ],
        )

    def test_capability_provenance_mismatch_fails_before_consumption(self):
        bad = provenance()
        bad["request_hash"] = "sha256:" + ("0" * 64)
        env = self.capability_environment(provenance_value=bad)
        capability = self.enter_with_patches(env)

        with self.assertRaises(ready.ExecutorReadyCapabilityError):
            with capability:
                self.fail("mismatched provenance unexpectedly accepted")

        self.assertFalse(env.lease._consumed)
        self.assertFalse(capability.lease_consumed)
        self.assertEqual(
            env.events,
            ["lease-enter", "auth-enter", "auth-exit", "lease-exit"],
        )

    def test_capability_reserved_scope_failure_releases_lease(self):
        env = self.capability_environment(fail_auth_enter=True)
        capability = self.enter_with_patches(env)

        with self.assertRaises(exauth.ExecutorAuthorizationError):
            with capability:
                self.fail("failed auth scope unexpectedly entered")

        self.assertFalse(env.lease._consumed)
        self.assertFalse(capability.lease_consumed)
        self.assertEqual(
            env.events,
            ["lease-enter", "auth-enter", "lease-exit"],
        )

    def test_capability_final_consume_failure_releases_auth_then_lease(self):
        env = self.capability_environment(fail_consume=True)
        capability = self.enter_with_patches(env)

        with self.assertRaises(leases.ExecutionLeaseError):
            with capability:
                self.fail("failed final consume unexpectedly entered")

        self.assertFalse(env.lease._consumed)
        self.assertFalse(capability.lease_consumed)
        self.assertEqual(
            env.events,
            [
                "lease-enter",
                "auth-enter",
                "lease-consume",
                "auth-exit",
                "lease-exit",
            ],
        )

    def test_post_consume_validation_failure_still_reports_actual_consumption(self):
        env = self.capability_environment()

        class ChangingAuthorizationScope(FakeAuthorizationScope):
            def __init__(self, events, current_record):
                super().__init__(events, current_record)
                self.reads = 0

            @property
            def record(self):
                if not self.entered:
                    raise RuntimeError("authorization scope inactive")
                self.reads += 1
                if self.reads == 1:
                    return self.current_record
                return object()

        env.auth_scope = ChangingAuthorizationScope(
            env.events,
            env.current_record,
        )
        capability = self.enter_with_patches(env)

        with self.assertRaisesRegex(
            ready.ExecutorReadyCapabilityError,
            "changed during final lease consumption",
        ):
            with capability:
                self.fail("post-consume validation failure unexpectedly entered")

        self.assertTrue(env.lease._consumed)
        self.assertTrue(capability.lease_consumed)
        self.assertFalse(capability.active)
        self.assertEqual(
            env.events,
            [
                "lease-enter",
                "auth-enter",
                "lease-consume",
                "auth-exit",
                "lease-exit",
            ],
        )

    def test_context_exit_burns_lease_and_invalidates_capability(self):
        env = self.capability_environment()
        capability = self.enter_with_patches(env)

        with capability:
            self.assertTrue(capability.active)
            self.assertTrue(env.lease._consumed)

        self.assertFalse(capability.active)
        self.assertTrue(capability.lease_consumed)
        self.assertTrue(env.lease._consumed)

        with self.assertRaises(ready.ExecutorReadyCapabilityError):
            _ = capability.handoff_id

        with self.assertRaisesRegex(
            ready.ExecutorReadyCapabilityError,
            "single-use",
        ):
            capability.__enter__()

    def test_capability_is_noncopyable_and_nonserializable(self):
        env = self.capability_environment()
        capability = self.enter_with_patches(env)

        with self.assertRaises(ready.ExecutorReadyCapabilityError):
            copy.copy(capability)
        with self.assertRaises(ready.ExecutorReadyCapabilityError):
            copy.deepcopy(capability)
        with self.assertRaises(ready.ExecutorReadyCapabilityError):
            pickle.dumps(capability)

    def test_capability_exposes_no_raw_fd_command_or_executor_surface(self):
        env = self.capability_environment()
        capability = self.enter_with_patches(env)

        with capability:
            for name in (
                "fd",
                "fileno",
                "write_claim",
                "held_reference",
                "read",
                "write",
                "seek",
                "callback",
                "command",
                "subprocess",
                "executor",
                "execute",
                "device_operation",
            ):
                self.assertFalse(hasattr(capability, name), name)

    def test_concurrent_reentry_allows_only_one_context_entry(self):
        env = self.capability_environment()
        capability = self.enter_with_patches(env)
        barrier = threading.Barrier(2)
        outcomes = []
        guard = threading.Lock()

        def worker():
            barrier.wait()
            try:
                capability.__enter__()
                outcome = "entered"
            except ready.ExecutorReadyCapabilityError:
                outcome = "refused"

            with guard:
                outcomes.append(outcome)

        threads = [
            threading.Thread(target=worker)
            for _ in range(2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(outcomes.count("entered"), 1)
        self.assertEqual(outcomes.count("refused"), 1)

        if capability.active:
            capability.__exit__(None, None, None)

    def test_source_has_no_device_io_command_subprocess_or_executor_action(self):
        source = Path(ready.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)

        for forbidden in (
            "import subprocess",
            "from subprocess",
            "Popen",
            "os.system",
            "ioctl",
            "wipefs",
            "mkfs",
            "shred",
        ):
            self.assertNotIn(forbidden, source)

        os_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
            ):
                os_calls.append(func.attr)

        self.assertEqual(os_calls, [])
        self.assertNotIn("def execute(", source)
        self.assertNotIn("def write(", source)
        self.assertIn(
            "durable authorization remains RESERVED",
            source,
        )


if __name__ == "__main__":
    unittest.main()
