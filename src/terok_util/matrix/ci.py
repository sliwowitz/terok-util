# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Run an approved checkout with a separately installed, trusted matrix engine.

CI accepts repository test phases, not host commands or Containerfile fragments.
The caller owns approval, immutable checkout preparation, credential isolation,
network policy, resource limits and process-group supervision. This entry point
does not turn privileged containers into a hostile-code security boundary.
``--krun`` isolates test kernels; trusted image builds and image probes still use
the host's default container runtime.
"""

from __future__ import annotations

import argparse
import re
import signal
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from terok_util.yaml import YAMLError

from . import cli
from ._files import read_regular
from .config import MatrixConfig, MatrixConfigError, _parse_config
from .runner import _sweep_namespace

__all__ = ["cleanup_ci", "run_ci"]

REPORT_NAME = "report.json"
_NAMESPACE = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]*")


def run_ci(
    repo: Path,
    output: Path,
    namespace: str,
    *,
    slots: tuple[str, ...] = (),
    krun: bool = False,
    jobs: int = 1,
) -> int:
    """Execute one matrix in a fresh caller-owned output directory.

    Args:
        repo: Absolute path to an immutable, disposable source checkout.
        output: New absolute directory outside the checkout, with an existing
            trusted parent. Contains ``report.json`` and per-slot files.
        namespace: Unique lowercase alphanumeric/hyphen run identifier, at most
            48 characters. Replaces the repository's image prefix.
        slots: Declared slot identifiers; empty selects all declared slots.
        krun: Use the microVM runtime for tests, not builds or image probes.
        jobs: Must be one; CI executes slots serially.

    Returns:
        The matrix exit code: zero for success, one for failed tests, two for an
        execution error, or 130 for an interruption.

    Raises:
        ValueError: The request or declaration violates CI policy.
        OSError: Source input is unsafe or the output directory cannot be created.
    """
    config, targets = _prepare(repo, output, namespace, slots, krun, jobs)
    output.mkdir(mode=0o700)
    scratch = output / "scratch"
    scratch.mkdir(mode=0o700)
    arguments = argparse.Namespace(
        report=output / REPORT_NAME,
        jobs=jobs,
        scope="all",
        build_only=False,
        no_cache=False,
        keep_dangling=False,
    )
    previous = signal.signal(signal.SIGTERM, cli._interrupt_on_sigterm)
    try:
        return cli._run_matrix(config, targets, arguments, scratch)
    finally:
        signal.signal(signal.SIGTERM, previous)


def main(argv: list[str] | None = None) -> int:
    """Parse the restricted CI interface without accepting arbitrary engine flags."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--namespace")
    parser.add_argument("--cleanup", metavar="NAMESPACE", help="remove only this run's containers")
    parser.add_argument("--krun", action="store_true")
    parser.add_argument("--jobs", type=int, choices=(1,), default=1)
    parser.add_argument("slots", nargs="*", help="declared slot names, after --")
    args = parser.parse_args(argv)
    try:
        if args.cleanup is not None:
            if args.repo or args.output or args.namespace or args.krun or args.slots:
                parser.error("--cleanup cannot be combined with run options")
            cleanup_ci(args.cleanup)
            return 0
        if args.repo is None or args.output is None or args.namespace is None:
            parser.error("--repo, --output and --namespace are required for a run")
        return run_ci(
            args.repo,
            args.output,
            args.namespace,
            slots=tuple(args.slots),
            krun=args.krun,
            jobs=args.jobs,
        )
    except (OSError, ValueError, YAMLError, subprocess.SubprocessError) as error:
        print(f"Matrix CI error: {error}", file=sys.stderr)
        return 2


def cleanup_ci(namespace: str) -> int:
    """Remove a run's containers after its engine stops, without reading its checkout.

    The supervisor must stop the engine process group before calling this method.
    Returns the number of removed containers; raises on a failed Podman command.
    """
    return _sweep_namespace(_image_prefix(namespace), check=True)


def _prepare(
    repo: Path,
    output: Path,
    namespace: str,
    slots: tuple[str, ...],
    krun: bool,
    jobs: int,
) -> tuple[MatrixConfig, list[str]]:
    """Validate all untrusted declarations before creating outputs or starting builds."""
    if not repo.is_absolute() or not output.is_absolute():
        raise ValueError("repo and output must be absolute paths")
    if not repo.is_dir():
        raise ValueError("repo must be an existing checkout directory")
    if output.exists() or output.is_symlink():
        raise ValueError("output must be a new directory")
    resolved_repo, resolved_output = repo.resolve(), output.resolve()
    if resolved_output.is_relative_to(resolved_repo) or resolved_repo.is_relative_to(
        resolved_output
    ):
        raise ValueError("repo and output must be separate directory trees")
    image_prefix = _image_prefix(namespace)
    if jobs != 1:
        raise ValueError("CI currently requires jobs=1")
    path = repo / cli.DEFAULT_CONFIG
    config = _parse_config(path, read_regular(path), strict=True)
    fragments = config.containers_dir / "fragments"
    if fragments.exists() or fragments.is_symlink():
        raise MatrixConfigError("CI does not accept repository Containerfile fragments")
    if any(
        not _PACKAGE.fullmatch(package)
        for slot in config.slots.values()
        for package in slot.extra_packages
    ):
        raise MatrixConfigError(
            "CI extra-packages must be plain package names, not options or paths"
        )
    targets = list(slots or config.slots)
    if not targets or len(set(targets)) != len(targets) or set(targets) - config.slots.keys():
        raise MatrixConfigError("CI slots must be distinct names declared by this repository")
    return replace(config, image_prefix=image_prefix, ci=True, krun=krun), targets


def _image_prefix(namespace: str) -> str:
    """Derive resource ownership from a bounded identifier, never a repository value."""
    if not _NAMESPACE.fullmatch(namespace):
        raise ValueError("namespace must contain 1-48 lowercase alphanumeric/hyphen characters")
    return f"ci-{namespace}"


if __name__ == "__main__":
    raise SystemExit(main())
