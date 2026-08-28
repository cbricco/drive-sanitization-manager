import ast
import copy
from contextlib import ExitStack
from datetime import datetime, timezone
import inspect
import pickle
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import execution_lease as lease


_NOW = datetime(
    2026, 8, 27, 18, 30, 0,
    tzinfo=timezone.utc,
)


class _HeldReference:
    def __init__(
        self,
        *,
        closed=False,
        handoff_id="xhnd_" + ("a" * 64),
        target_path="/dev/synthetic-b3fa-r2-target",
        target_major_minor="8:0",
        target_binding_hash="sha256:" + ("b" * 64),
    ):
        self.closed = closed
        self.handoff_id = handoff_id
        self.target_path = target_path
        self.target_major_minor = target_major_minor
        self.target_binding_hash = target_binding_hash


class _WriteClaim:
    def __init__(
        self,
        *,
        held_reference=None,
        closed=False,
        handoff_id="xhnd_" + ("a" * 64),
        target_path="/dev/synthetic-b3fa-r2-target",
        target_major_minor="8:0",
        target_binding_hash="sha256:" + ("b" * 64),
        pre_continuity_id="hsc_" + ("c" * 64),
        post_continuity_id="hsc_" + ("d" * 64),
    ):
        if held_reference is None:
            held_reference = _HeldReference(
                handoff_id=handoff_id,
                target_path=target_path,
                target_major_minor=target_major_minor,
                target_binding_hash=target_binding_hash,
            )
        self.held_reference = held_reference
        self.closed = closed
        self.handoff_id = handoff_id
        self.target_path = target_path
        self.target_major_minor = target_major_minor
        self.target_binding_hash = target_binding_hash
        self.pre_continuity_id = pre_continuity_id
        self.post_continuity_id = post_continuity_id


class _Continuity:
    def __init__(
        self,
        *,
        continuity_id="hsc_" + ("e" * 64),
        handoff_id="xhnd_" + ("a" * 64),
        target_path="/dev/synthetic-b3fa-r2-target",
        target_major_minor="8:0",
        target_binding_hash="sha256:" + ("b" * 64),
        evaluated_at_utc="2026-08-27T18:29:55Z",
        valid_until_utc="2026-08-27T18:34:55Z",
        execution_supported=False,
        executor_eligible=False,
        requires_separate_executor_authorization=True,
        integrity=True,
    ):
        self.continuity_id = continuity_id
        self.handoff_id = handoff_id
        self.target_path = target_path
        self.target_major_minor = target_major_minor
        self.target_binding_hash = target_binding_hash
        self.evaluated_at_utc = evaluated_at_utc
        self.valid_until_utc = valid_until_utc
        self.execution_supported = execution_supported
        self.executor_eligible = executor_eligible
        self.requires_separate_executor_authorization = (
            requires_separate_executor_authorization
        )
        self.integrity = integrity


class _Scope:
    def __init__(
        self,
        write_claim,
        descriptor_hook,
    ):
        self._claim = write_claim
        self._descriptor_hook = descriptor_hook
        self._entered = False

    def __enter__(self):
        if (
            self._claim.closed
            or self._claim.held_reference.closed
        ):
            raise RuntimeError("synthetic closed claim")
        self._entered = True
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self._entered = False
        return False

    @property
    def held_reference(self):
        if not self._entered:
            raise RuntimeError("scope is not entered")
        return self._claim.held_reference

    @property
    def identity(self):
        if not self._entered:
            raise RuntimeError("scope is not entered")
        return (
            self._claim.handoff_id,
            self._claim.target_path,
            self._claim.target_major_minor,
            self._claim.target_binding_hash,
        )

    @property
    def claim_pre_continuity_id(self):
        return self._claim.pre_continuity_id

    @property
    def claim_post_continuity_id(self):
        return self._claim.post_continuity_id

    def revalidate_descriptor(self):
        if not self._entered:
            raise RuntimeError("scope is not entered")
        self._descriptor_hook()
        return self._claim.target_major_minor


class ExecutionLeaseR2Tests(unittest.TestCase):
    def setUp(self):
        lease._ISSUED_CLAIMS.clear()

    def claim(self, **changes):
        return _WriteClaim(**changes)

    def continuity(self, **changes):
        return _Continuity(**changes)

    def environment(
        self,
        *,
        create_before=None,
        create_after=None,
        consume_before=None,
        consume_after=None,
        descriptor_side_effect=None,
        nonce=None,
    ):
        if create_before is None:
            create_before = self.continuity(
                continuity_id="hsc_" + ("e" * 64),
            )
        if create_after is None:
            create_after = self.continuity(
                continuity_id="hsc_" + ("f" * 64),
            )
        if consume_before is None:
            consume_before = self.continuity(
                continuity_id="hsc_" + ("1" * 64),
            )
        if consume_after is None:
            consume_after = self.continuity(
                continuity_id="hsc_" + ("2" * 64),
            )
        if nonce is None:
            nonce = "3" * 64

        stack = ExitStack()

        stack.enter_context(
            patch.object(
                lease.claims,
                "HeldKernelWriteClaim",
                _WriteClaim,
            )
        )
        revalidate = stack.enter_context(
            patch.object(
                lease.continuity,
                "revalidate_held_target_safety_continuity",
                side_effect=[
                    create_before,
                    create_after,
                    consume_before,
                    consume_after,
                ],
            )
        )
        integrity = stack.enter_context(
            patch.object(
                lease.continuity,
                "_held_target_safety_continuity_integrity_valid",
                side_effect=lambda decision: decision.integrity,
            )
        )
        stack.enter_context(
            patch.object(
                lease.continuity,
                "HeldTargetSafetyContinuityDecision",
                _Continuity,
            )
        )
        descriptor = Mock(
            side_effect=descriptor_side_effect
        )
        scope_factory = stack.enter_context(
            patch.object(
                lease.claims,
                "_locked_write_claim_validation_scope",
                side_effect=lambda write_claim: _Scope(
                    write_claim,
                    descriptor,
                ),
            )
        )
        token_hex = stack.enter_context(
            patch.object(
                lease.secrets,
                "token_hex",
                return_value=nonce,
            )
        )
        stack.enter_context(
            patch.object(
                lease,
                "_utc_now",
                return_value=_NOW,
            )
        )

        return SimpleNamespace(
            stack=stack,
            revalidate=revalidate,
            integrity=integrity,
            descriptor=descriptor,
            scope_factory=scope_factory,
            token_hex=token_hex,
        )

    def create(self, write_claim):
        return lease.create_execution_lease(
            write_claim=write_claim,
            registry=object(),
            approval_id="approval",
            request=object(),
            record=object(),
            journal=object(),
            gate=object(),
        )

    def test_success_is_synchronized_bound_and_non_authorizing(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            result = self.create(write_claim)

            self.assertTrue(result.live)
            self.assertFalse(result.consumed)
            self.assertTrue(
                result.execution_authorization_integrity_binding_id.startswith(
                    "xeli_"
                )
            )
            self.assertTrue(result.internal_integrity_binding_only)
            self.assertFalse(result.external_authorization_proven)
            self.assertFalse(result.execution_authorized)
            self.assertFalse(result.execution_supported)
            self.assertFalse(result.executor_eligible)
            self.assertTrue(
                result.requires_trusted_executor_consumption
            )
            self.assertFalse(
                result.absolute_write_exclusion_guaranteed
            )
            self.assertFalse(
                result.ordinary_raw_writers_excluded
            )
            self.assertEqual(mocks.revalidate.call_count, 2)
            self.assertEqual(mocks.descriptor.call_count, 2)

    def test_builder_accepts_no_fd_path_continuity_or_executor_substitution(self):
        parameters = inspect.signature(
            lease.create_execution_lease
        ).parameters

        for forbidden in (
            "fd",
            "fileno",
            "path",
            "target_path",
            "continuity",
            "continuity_decision",
            "callback",
            "command",
            "subprocess",
            "executor",
            "opener",
            "open_fn",
            "authorization_binding",
        ):
            self.assertNotIn(
                forbidden,
                parameters,
            )

    def test_wrong_claim_type_fails_before_scope_or_continuity(self):
        mocks = self.environment()

        with mocks.stack:
            with self.assertRaises(
                lease.ExecutionLeaseError
            ):
                self.create(SimpleNamespace())

        mocks.scope_factory.assert_not_called()
        mocks.revalidate.assert_not_called()
        mocks.descriptor.assert_not_called()

    def test_creation_generates_two_fresh_continuity_checks(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            self.create(write_claim)

        self.assertEqual(mocks.revalidate.call_count, 2)
        self.assertEqual(mocks.integrity.call_count, 2)
        self.assertEqual(mocks.descriptor.call_count, 2)

    def test_creation_stale_continuity_fails_before_binding(self):
        stale = self.continuity(
            evaluated_at_utc="2026-08-27T17:00:00Z",
            valid_until_utc="2026-08-27T17:05:00Z",
        )
        write_claim = self.claim()
        mocks = self.environment(
            create_before=stale,
        )

        with mocks.stack:
            with self.assertRaises(
                lease.ExecutionLeaseError
            ):
                self.create(write_claim)

        mocks.token_hex.assert_not_called()

    def test_creation_integrity_failure_fails_before_binding(self):
        failed = self.continuity(
            integrity=False,
        )
        write_claim = self.claim()
        mocks = self.environment(
            create_before=failed,
        )

        with mocks.stack:
            with self.assertRaises(
                lease.ExecutionLeaseError
            ):
                self.create(write_claim)

        mocks.token_hex.assert_not_called()

    def test_creation_descriptor_failure_never_issues_lease(self):
        write_claim = self.claim()
        mocks = self.environment(
            descriptor_side_effect=RuntimeError(
                "synthetic descriptor failure"
            ),
        )

        with mocks.stack:
            with self.assertRaisesRegex(
                lease.ExecutionLeaseError,
                "descriptor validation failed",
            ):
                self.create(write_claim)

        self.assertEqual(
            lease._ISSUED_CLAIMS,
            {},
        )
        mocks.token_hex.assert_not_called()

    def test_post_creation_continuity_identity_change_fails(self):
        changed = self.continuity(
            continuity_id="hsc_" + ("f" * 64),
            target_major_minor="8:16",
        )
        write_claim = self.claim()
        mocks = self.environment(
            create_after=changed,
        )

        with mocks.stack:
            with self.assertRaises(
                lease.ExecutionLeaseError
            ):
                self.create(write_claim)

        mocks.token_hex.assert_not_called()

    def test_no_second_lease_for_same_claim(self):
        write_claim = self.claim()

        first = self.environment()
        with first.stack:
            result = self.create(write_claim)
            self.assertTrue(result.live)

        second = self.environment(
            nonce="4" * 64,
        )
        with second.stack:
            with self.assertRaisesRegex(
                lease.ExecutionLeaseError,
                "already has an issued",
            ):
                self.create(write_claim)

        second.token_hex.assert_not_called()

    def test_distinct_claims_get_distinct_integrity_bindings(self):
        first_claim = self.claim()
        second_claim = self.claim()

        first_env = self.environment(
            nonce="3" * 64,
        )
        with first_env.stack:
            first = self.create(first_claim)

        second_env = self.environment(
            nonce="4" * 64,
        )
        with second_env.stack:
            second = self.create(second_claim)

        self.assertNotEqual(
            first.execution_authorization_integrity_binding_id,
            second.execution_authorization_integrity_binding_id,
        )

    def test_invalid_nonce_fails_closed(self):
        write_claim = self.claim()
        mocks = self.environment(
            nonce="not-hex",
        )

        with mocks.stack:
            with self.assertRaisesRegex(
                lease.ExecutionLeaseError,
                "nonce is invalid",
            ):
                self.create(write_claim)

        self.assertEqual(
            lease._ISSUED_CLAIMS,
            {},
        )

    def test_consume_runs_fresh_continuity_and_descriptor_cycle(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            result = self.create(write_claim)
            self.assertEqual(mocks.revalidate.call_count, 2)
            self.assertEqual(mocks.descriptor.call_count, 2)

            result.consume()

            self.assertTrue(result.consumed)
            self.assertFalse(result.live)
            self.assertEqual(mocks.revalidate.call_count, 4)
            self.assertEqual(mocks.integrity.call_count, 4)
            self.assertEqual(mocks.descriptor.call_count, 4)

    def test_consume_rejects_stale_fresh_safety_without_consuming(self):
        stale = self.continuity(
            continuity_id="hsc_" + ("1" * 64),
            evaluated_at_utc="2026-08-27T17:00:00Z",
            valid_until_utc="2026-08-27T17:05:00Z",
        )
        write_claim = self.claim()
        mocks = self.environment(
            consume_before=stale,
        )

        with mocks.stack:
            result = self.create(write_claim)

            with self.assertRaises(
                lease.ExecutionLeaseError
            ):
                result.consume()

            self.assertFalse(result.consumed)

    def test_consume_rejects_post_safety_identity_change(self):
        changed = self.continuity(
            continuity_id="hsc_" + ("2" * 64),
            target_major_minor="8:16",
        )
        write_claim = self.claim()
        mocks = self.environment(
            consume_after=changed,
        )

        with mocks.stack:
            result = self.create(write_claim)

            with self.assertRaises(
                lease.ExecutionLeaseError
            ):
                result.consume()

            self.assertFalse(result.consumed)

    def test_consume_descriptor_failure_does_not_consume(self):
        write_claim = self.claim()
        mocks = self.environment(
            descriptor_side_effect=[
                None,
                None,
                RuntimeError("synthetic consumption descriptor failure"),
            ],
        )

        with mocks.stack:
            result = self.create(write_claim)

            with self.assertRaisesRegex(
                lease.ExecutionLeaseError,
                "descriptor validation failed",
            ):
                result.consume()

            self.assertFalse(result.consumed)

    def test_binding_tamper_blocks_consumption(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            result = self.create(write_claim)
            result._execution_authorization_integrity_binding_id = (
                "xeli_" + ("0" * 64)
            )

            with self.assertRaisesRegex(
                lease.ExecutionLeaseError,
                "integrity binding failed",
            ):
                result.consume()

            self.assertFalse(result.consumed)

    def test_claim_or_b3a_closure_blocks_consumption(self):
        for target in ("claim", "b3a"):
            with self.subTest(target=target):
                lease._ISSUED_CLAIMS.clear()
                write_claim = self.claim()
                mocks = self.environment()

                with mocks.stack:
                    result = self.create(write_claim)

                    if target == "claim":
                        write_claim.closed = True
                    else:
                        write_claim.held_reference.closed = True

                    with self.assertRaises(
                        lease.ExecutionLeaseError
                    ):
                        result.consume()

                    self.assertFalse(result.consumed)

    def test_concurrent_consumption_allows_exactly_one_success(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            result = self.create(write_claim)

            barrier = threading.Barrier(8)
            outcomes = []
            guard = threading.Lock()

            def worker():
                barrier.wait()
                try:
                    result.consume()
                    outcome = "success"
                except lease.ExecutionLeaseError:
                    outcome = "refused"

                with guard:
                    outcomes.append(outcome)

            threads = [
                threading.Thread(target=worker)
                for _ in range(8)
            ]

            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(
                outcomes.count("success"),
                1,
            )
            self.assertEqual(
                outcomes.count("refused"),
                7,
            )
            self.assertTrue(result.consumed)
            self.assertEqual(mocks.revalidate.call_count, 4)
            self.assertEqual(mocks.descriptor.call_count, 4)

    def test_lease_cannot_be_copied_or_serialized(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            result = self.create(write_claim)

            for operation in (
                lambda: copy.copy(result),
                lambda: copy.deepcopy(result),
                lambda: pickle.dumps(result),
            ):
                with self.subTest(operation=operation):
                    with self.assertRaises(
                        lease.ExecutionLeaseError
                    ):
                        operation()

    def test_public_lease_surface_exposes_no_io_callback_command_or_executor(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            result = self.create(write_claim)

            for name in (
                "fd",
                "fileno",
                "read",
                "write",
                "seek",
                "callback",
                "command",
                "subprocess",
                "executor",
                "execute",
            ):
                self.assertFalse(
                    hasattr(result, name),
                    name,
                )

            self.assertFalse(
                hasattr(result, "__dict__")
            )

    def test_source_uses_only_locked_scope_and_has_no_direct_fd_or_device_open(self):
        source = Path(lease.__file__).read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)

        forbidden_os_calls = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
                and func.attr in {
                    "open",
                    "read",
                    "write",
                    "pread",
                    "pwrite",
                    "lseek",
                }
            ):
                forbidden_os_calls.append(func.attr)

        self.assertEqual(
            forbidden_os_calls,
            [],
        )
        self.assertNotIn(
            "write_claim._fd",
            source,
        )
        self.assertNotIn(
            "write_claim._held_reference",
            source,
        )
        self.assertIn(
            "_locked_write_claim_validation_scope",
            source,
        )

        for forbidden in (
            "import subprocess",
            "from subprocess",
            "Popen",
            "ioctl",
            "O_WRONLY",
            "os.open",
        ):
            self.assertNotIn(
                forbidden,
                source,
            )

        self.assertEqual(
            lease.__all__,
            [
                "EXECUTION_LEASE_POLICY_VERSION",
                "ExecutionLease",
                "ExecutionLeaseError",
                "create_execution_lease",
            ],
        )

    def test_r3_consumed_property_waits_for_in_progress_consume(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            result = self.create(write_claim)
            entered = threading.Event()
            release = threading.Event()
            observed = []
            observed_done = threading.Event()

            def blocked_cycle(**kwargs):
                entered.set()
                if not release.wait(1.0):
                    raise RuntimeError(
                        "synthetic consume release timeout"
                    )
                return (
                    "hsc_" + ("7" * 64),
                    "hsc_" + ("8" * 64),
                )

            with patch.object(
                lease,
                "_fresh_safety_cycle",
                side_effect=blocked_cycle,
            ):
                consume_thread = threading.Thread(
                    target=result.consume
                )
                consume_thread.start()
                self.assertTrue(entered.wait(1.0))

                def reader():
                    observed.append(result.consumed)
                    observed_done.set()

                reader_thread = threading.Thread(
                    target=reader
                )
                reader_thread.start()

                self.assertFalse(
                    observed_done.wait(0.05)
                )

                release.set()
                consume_thread.join(1.0)
                reader_thread.join(1.0)

            self.assertFalse(consume_thread.is_alive())
            self.assertFalse(reader_thread.is_alive())
            self.assertEqual(observed, [True])

    def test_r3_live_cannot_return_stale_true_across_concurrent_consume(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            result = self.create(write_claim)
            entered = threading.Event()
            release = threading.Event()
            observed = []
            observed_done = threading.Event()

            def blocked_cycle(**kwargs):
                entered.set()
                if not release.wait(1.0):
                    raise RuntimeError(
                        "synthetic consume release timeout"
                    )
                return (
                    "hsc_" + ("7" * 64),
                    "hsc_" + ("8" * 64),
                )

            with patch.object(
                lease,
                "_fresh_safety_cycle",
                side_effect=blocked_cycle,
            ):
                consume_thread = threading.Thread(
                    target=result.consume
                )
                consume_thread.start()
                self.assertTrue(entered.wait(1.0))

                def reader():
                    observed.append(result.live)
                    observed_done.set()

                reader_thread = threading.Thread(
                    target=reader
                )
                reader_thread.start()

                self.assertFalse(
                    observed_done.wait(0.05)
                )

                release.set()
                consume_thread.join(1.0)
                reader_thread.join(1.0)

            self.assertFalse(consume_thread.is_alive())
            self.assertFalse(reader_thread.is_alive())
            self.assertEqual(observed, [False])
            self.assertTrue(result.consumed)

    def test_r3_consumed_transition_occurs_before_claim_scope_exit(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            result = self.create(write_claim)
            exit_observations = []

            class RecordingScope(_Scope):
                def __exit__(
                    self,
                    exc_type,
                    exc,
                    traceback,
                ):
                    exit_observations.append(
                        result._consumed
                    )
                    return super().__exit__(
                        exc_type,
                        exc,
                        traceback,
                    )

            with patch.object(
                lease.claims,
                "_locked_write_claim_validation_scope",
                side_effect=lambda claim_value: RecordingScope(
                    claim_value,
                    mocks.descriptor,
                ),
            ):
                result.consume()

            self.assertEqual(
                exit_observations,
                [True],
            )
            self.assertTrue(result.consumed)

    def test_r3_consume_failure_releases_state_and_claim_scopes(self):
        write_claim = self.claim()
        mocks = self.environment()

        with mocks.stack:
            result = self.create(write_claim)

            with patch.object(
                lease,
                "_fresh_safety_cycle",
                side_effect=RuntimeError(
                    "synthetic R3 consume failure"
                ),
            ):
                with self.assertRaises(
                    lease.ExecutionLeaseError
                ):
                    result.consume()

            self.assertFalse(result.consumed)
            self.assertTrue(result.live)


if __name__ == "__main__":
    unittest.main()
