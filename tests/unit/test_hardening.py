# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for [`harden_self`][terok_util.hardening.harden_self].

The real-syscall behaviour is exercised in a fresh interpreter
(``subprocess``) so the floor's side effects — a cleared dumpable flag,
a zeroed core limit, and possibly ``mlockall`` — never bleed into the
pytest runner (a privileged runner that locked memory could otherwise
hit ``RLIMIT_MEMLOCK`` in later tests).  The branch/report logic is
checked in-process with the syscalls stubbed out.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

from terok_util import hardening
from terok_util.hardening import HardeningReport, harden_self

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="hardening floor is Linux-only")


def test_real_syscalls_take_effect() -> None:
    """In a fresh process the dumpable flag and core limit are actually cleared."""
    probe = textwrap.dedent(
        """
        import ctypes, ctypes.util, resource
        from terok_util.hardening import harden_self

        report = harden_self()
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        _PR_GET_DUMPABLE = 3
        dumpable = libc.prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0)
        soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
        print(f"{int(report.no_dump)}{int(report.no_core)}:{dumpable}:{soft}:{hard}")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    flags, dumpable, soft, hard = result.stdout.strip().split(":")
    assert flags == "11", "no_dump and no_core must both succeed in a normal process"
    assert dumpable == "0", "PR_GET_DUMPABLE must read back 0 after harden_self"
    assert (soft, hard) == ("0", "0"), "RLIMIT_CORE must be pinned to zero"


def test_non_linux_reports_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Off Linux the floor no-ops and every guarantee reads ``False``."""
    monkeypatch.setattr(hardening.sys, "platform", "darwin")
    report = harden_self()
    assert report == HardeningReport(no_dump=False, no_core=False, memory_locked=False)


def test_core_limit_is_independent_of_libc(monkeypatch: pytest.MonkeyPatch) -> None:
    """With libc unreachable, the pure-``resource`` core-limit clear still takes."""
    monkeypatch.setattr(hardening, "_libc", lambda: None)
    report = harden_self()
    assert report.no_dump is False
    assert report.memory_locked is False
    assert report.no_core is True


class TestHardeningReport:
    """The ``fully_hardened`` roll-up is a plain three-way AND."""

    def test_all_true_is_fully_hardened(self) -> None:
        assert HardeningReport(no_dump=True, no_core=True, memory_locked=True).fully_hardened

    @pytest.mark.parametrize(
        ("no_dump", "no_core", "memory_locked"),
        [(False, True, True), (True, False, True), (True, True, False)],
    )
    def test_any_gap_is_not_fully_hardened(
        self, no_dump: bool, no_core: bool, memory_locked: bool
    ) -> None:
        report = HardeningReport(no_dump=no_dump, no_core=no_core, memory_locked=memory_locked)
        assert not report.fully_hardened
