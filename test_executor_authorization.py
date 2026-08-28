from contextlib import ExitStack
from datetime import datetime, timezone
import inspect
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import executor_authorization as exauth


_NOW = datetime(2026, 8, 28, 7, 0, 0, tzinfo=timezone.utc)


class _Lease:
    pass


class _LeaseScope:
    def __init__(
        self,
        lease,
        *,
        identity=None,
        binding_id=None,
        tracker=None,
    ):
        self.lease = lease
        self.identity_value = identity or (
            "xhnd_" + ("a" * 64),
            "/synthetic/b3fb",
            "8:0",
            "sha256:" + ("b" * 64),
        )
        self.binding_value = binding_id or "xeli_" + ("c" * 64)
        self.tracker = tracker
        self.entered = False

    def __enter__(self):
        self.entered = True
        if self.tracker is not None:
            self.tracker["active"] = True
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.entered = False
        if self.tracker is not None:
            self.tracker["active"] = False
        return False

    @property
    def identity(self):
        if not self.entered:
            raise RuntimeError("fake lease scope inactive")
        return self.identity_value

    @property
    def execution_authorization_integrity_binding_id(self):
        if not self.entered:
            raise RuntimeError("fake lease scope inactive")
        return self.binding_value


class _Handoff:
    def __init__(self):
        self.handoff_id = "xhnd_" + ("a" * 64)
        self.gate_id = "xgate_" + ("d" * 64)
        self.binding_id = "xeb_" + ("e" * 64)
        self.journal_policy_version = "journal-policy"
        self.journal_schema_version = 1
        self.journal_state = "completed"
        self.journal_entry_hash = "sha256:" + ("f" * 64)
        self.approval_id = "appr_synthetic"
        self.request_id = "request-synthetic"
        self.request_hash = "sha256:" + ("1" * 64)
        self.record_snapshot_hash = "sha256:" + ("2" * 64)
        self.internal_record_id = "record-synthetic"
        self.method_profile_id = "synthetic-method"
        self.operation = "sanitize"
        self.target_binding_hash = "sha256:" + ("b" * 64)


class _JournalEntry:
    def __init__(self, handoff):
        self.binding_id = handoff.binding_id
        self.state = handoff.journal_state
        self.request_hash = handoff.request_hash
        self.record_snapshot_hash = handoff.record_snapshot_hash
        self.target_binding_hash = handoff.target_binding_hash
        self.reserved_at_utc = "2026-08-28T06:59:00.000000Z"
        self.gate_id = handoff.gate_id
        self.completed_at_utc = "2026-08-28T06:59:30.000000Z"
        self.entry_hash = handoff.journal_entry_hash


class _Journal:
    def __init__(self, handoff):
        self.entry = _JournalEntry(handoff)

    def entry_for_binding(self, binding_id):
        return self.entry if binding_id == self.entry.binding_id else None


class ExecutorAuthorizationTests(unittest.TestCase):
    def setUp(self):
        exauth._LIVE_AUTHORIZATIONS.clear()

    def private_dir(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name)
        os.chmod(path, 0o700)
        return path

    def store(self):
        return exauth.DurableExecutorAuthorizationStore(
            self.private_dir() / "executor-authorizations.json"
        )

    def environment(
        self,
        *,
        identity=None,
        binding_id=None,
        tracker=None,
    ):
        handoff = _Handoff()
        journal = _Journal(handoff)
        lease = _Lease()
        stack = ExitStack()

        for name, value in (
            ("_HANDOFF_TYPE", _Handoff),
            ("_JOURNAL_TYPE", _Journal),
            ("_JOURNAL_ENTRY_TYPE", _JournalEntry),
            ("_LEASE_TYPE", _Lease),
        ):
            stack.enter_context(patch.object(exauth, name, value))

        stack.enter_context(
            patch.object(
                exauth,
                "_HANDOFF_INTEGRITY_VALIDATOR",
                side_effect=lambda value: isinstance(value, _Handoff),
            )
        )
        stack.enter_context(
            patch.object(
                exauth,
                "_JOURNAL_ENTRY_VALIDATOR",
                side_effect=lambda value: isinstance(value, _JournalEntry),
            )
        )
        stack.enter_context(
            patch.object(
                exauth,
                "_COMPLETED_JOURNAL_STATE",
                handoff.journal_state,
            )
        )
        stack.enter_context(
            patch.object(
                exauth.auth,
                "DURABLE_GATE_JOURNAL_POLICY_VERSION",
                handoff.journal_policy_version,
            )
        )
        stack.enter_context(
            patch.object(
                exauth.auth,
                "DURABLE_GATE_JOURNAL_SCHEMA_VERSION",
                handoff.journal_schema_version,
            )
        )
        stack.enter_context(
            patch.object(
                exauth,
                "_LEASE_SCOPE_FACTORY",
                side_effect=lambda value: _LeaseScope(
                    value,
                    identity=identity,
                    binding_id=binding_id,
                    tracker=tracker,
                ),
            )
        )
        stack.enter_context(
            patch.object(exauth, "_utc_now", return_value=_NOW)
        )
        stack.enter_context(
            patch.object(
                exauth.secrets,
                "token_hex",
                return_value="9" * 64,
            )
        )

        return SimpleNamespace(
            stack=stack,
            handoff=handoff,
            journal=journal,
            lease=lease,
        )

    def issue(self, store, env):
        return exauth.record_trusted_executor_authorization(
            store=store,
            lease=env.lease,
            handoff=env.handoff,
            journal=env.journal,
        )

    def test_exact_binding_private_mode_and_internal_xeli_semantics(self):
        store = self.store()
        env = self.environment()
        with env.stack:
            record = self.issue(store, env)

        self.assertEqual(
            record.state,
            exauth.EXECUTOR_AUTHORIZATION_STATE_AUTHORIZED,
        )
        self.assertEqual(record.lease_binding_id, "xeli_" + ("c" * 64))
        self.assertEqual(record.target_major_minor, "8:0")
        self.assertEqual(record.handoff_id, env.handoff.handoff_id)
        self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)
        self.assertTrue(exauth._record_integrity_valid(record))

    def test_trusted_issuance_has_no_caller_authority_substitution(self):
        parameters = inspect.signature(
            exauth.record_trusted_executor_authorization
        ).parameters
        for forbidden in (
            "approved",
            "approval",
            "timestamp",
            "authorized_at",
            "nonce",
            "authorization_record",
            "continuity",
            "continuity_decision",
            "executor",
            "command",
        ):
            self.assertNotIn(forbidden, parameters)

    def test_duplicate_issue_and_exact_provenance_mismatch_fail_closed(self):
        store = self.store()
        first = self.environment()
        with first.stack:
            self.issue(store, first)

        duplicate = self.environment()
        with duplicate.stack:
            with self.assertRaises(exauth.ExecutorAuthorizationError):
                self.issue(store, duplicate)

        other = self.store()
        mismatch = self.environment(
            identity=(
                "xhnd_" + ("0" * 64),
                "/synthetic/b3fb",
                "8:0",
                "sha256:" + ("b" * 64),
            )
        )
        with mismatch.stack:
            with self.assertRaises(exauth.ExecutorAuthorizationError):
                self.issue(other, mismatch)
        self.assertFalse(other.path.exists())

    def test_restart_invalidates_live_capability_but_preserves_authorized_tombstone(self):
        store = self.store()
        env = self.environment()
        with env.stack:
            record = self.issue(store, env)
            exauth._LIVE_AUTHORIZATIONS.clear()
            with self.assertRaisesRegex(
                exauth.ExecutorAuthorizationError,
                "restart/recreation",
            ):
                exauth.reserve_executor_authorization(
                    store=store,
                    authorization_id=record.authorization_id,
                    lease=env.lease,
                )

        persisted = store.entry_for_authorization(record.authorization_id)
        self.assertEqual(
            persisted.state,
            exauth.EXECUTOR_AUTHORIZATION_STATE_AUTHORIZED,
        )

    def test_reserved_state_blocks_replay_and_represents_crash_ambiguity(self):
        store = self.store()
        env = self.environment()
        with env.stack:
            record = self.issue(store, env)
            reserved = exauth.reserve_executor_authorization(
                store=store,
                authorization_id=record.authorization_id,
                lease=env.lease,
            )
            self.assertEqual(
                reserved.state,
                exauth.EXECUTOR_AUTHORIZATION_STATE_RESERVED,
            )
            with self.assertRaises(exauth.ExecutorAuthorizationError):
                exauth.reserve_executor_authorization(
                    store=store,
                    authorization_id=record.authorization_id,
                    lease=env.lease,
                )

            exauth._LIVE_AUTHORIZATIONS.clear()
            persisted = store.entry_for_authorization(
                record.authorization_id
            )
            self.assertEqual(
                persisted.state,
                exauth.EXECUTOR_AUTHORIZATION_STATE_RESERVED,
            )

    def test_concurrent_one_shot_reservation_allows_one_success(self):
        store = self.store()
        env = self.environment()
        with env.stack:
            record = self.issue(store, env)
            barrier = threading.Barrier(6)
            outcomes = []
            guard = threading.Lock()

            def worker():
                barrier.wait()
                try:
                    exauth.reserve_executor_authorization(
                        store=store,
                        authorization_id=record.authorization_id,
                        lease=env.lease,
                    )
                    outcome = "success"
                except exauth.ExecutorAuthorizationError:
                    outcome = "refused"
                with guard:
                    outcomes.append(outcome)

            threads = [threading.Thread(target=worker) for _ in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(outcomes.count("success"), 1)
        self.assertEqual(outcomes.count("refused"), 5)

    def test_tamper_and_malformed_store_fail_closed(self):
        for mode in ("tamper", "malformed"):
            with self.subTest(mode=mode):
                exauth._LIVE_AUTHORIZATIONS.clear()
                store = self.store()
                env = self.environment()
                with env.stack:
                    record = self.issue(store, env)

                if mode == "tamper":
                    document = json.loads(
                        store.path.read_text(encoding="utf-8")
                    )
                    document["entries"][0]["operation"] = "tampered"
                    store.path.write_text(
                        json.dumps(document) + "\n",
                        encoding="utf-8",
                    )
                else:
                    store.path.write_text(
                        "{not-json\n",
                        encoding="utf-8",
                    )
                os.chmod(store.path, 0o600)

                with self.assertRaises(exauth.ExecutorAuthorizationError):
                    store.entry_for_authorization(
                        record.authorization_id
                    )

    def test_symlink_and_permission_failures_are_refused(self):
        parent = self.private_dir()
        target = parent / "real.json"
        target.write_text("{}", encoding="utf-8")
        os.chmod(target, 0o600)
        link = parent / "executor-authorizations.json"
        link.symlink_to(target)

        env = self.environment()
        with env.stack:
            with self.assertRaises(exauth.ExecutorAuthorizationError):
                self.issue(
                    exauth.DurableExecutorAuthorizationStore(link),
                    env,
                )

        insecure = self.private_dir()
        os.chmod(insecure, 0o755)
        env2 = self.environment()
        with env2.stack:
            with self.assertRaises(exauth.ExecutorAuthorizationError):
                self.issue(
                    exauth.DurableExecutorAuthorizationStore(
                        insecure / "executor-authorizations.json"
                    ),
                    env2,
                )

    def test_atomic_replace_failure_returns_no_authorization(self):
        store = self.store()
        env = self.environment()
        with env.stack:
            with patch.object(
                exauth.os,
                "replace",
                side_effect=OSError("synthetic replace failure"),
            ):
                with self.assertRaises(exauth.ExecutorAuthorizationError):
                    self.issue(store, env)
        self.assertFalse(store.path.exists())

    def test_existing_store_wrong_mode_fails_closed(self):
        store = self.store()
        env = self.environment()
        with env.stack:
            record = self.issue(store, env)

        os.chmod(store.path, 0o644)
        with self.assertRaises(exauth.ExecutorAuthorizationError):
            store.entry_for_authorization(record.authorization_id)

    def test_store_mutation_occurs_only_while_live_lease_scope_is_pinned(self):
        tracker = {"active": False}
        store = self.store()
        env = self.environment(tracker=tracker)
        original = store._authorize

        def checked(provenance):
            self.assertTrue(tracker["active"])
            return original(provenance)

        with env.stack:
            with patch.object(store, "_authorize", side_effect=checked):
                self.issue(store, env)

        self.assertFalse(tracker["active"])

    def test_source_has_no_executor_command_or_block_device_surface(self):
        source = Path(exauth.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "import subprocess",
            "from subprocess",
            "Popen",
            "os.system",
            "ioctl",
            "/dev/",
            "wipefs",
            "mkfs",
            "shred",
        ):
            self.assertNotIn(forbidden, source)

        self.assertIn(
            "xeli_ value is used only as exact live-lease identity",
            source,
        )
        self.assertIn("does not execute sanitization", source)


if __name__ == "__main__":
    unittest.main()
