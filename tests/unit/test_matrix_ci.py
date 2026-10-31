# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""CI policy rejects host influence while preserving in-container test declarations."""

from __future__ import annotations

import json
import os
import signal
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from terok_util.matrix import ci, cli, runner
from terok_util.matrix._files import read_regular
from terok_util.matrix.catalog import INPUTS_MOUNT, OWNERSHIP_LABEL, RESULTS_MOUNT
from unit.matrix_fixtures import load_fixture, minimal_yml, write_config


@pytest.fixture
def source(tmp_path: Path) -> Path:
    """Provide a disposable checkout beside its future output directory."""
    repo = tmp_path / "repo"
    write_config(repo, minimal_yml())
    return repo


@pytest.mark.parametrize(
    "namespace", ["../escape", "/escape", "-option", "bad:name", "A", "x" * 49]
)
def test_namespace_rejected_before_execution(source: Path, tmp_path: Path, namespace: str) -> None:
    """Host resource names cannot be paths, options, or uncontrolled strings."""
    with pytest.raises(ValueError, match="namespace"):
        ci.run_ci(source, tmp_path / "output", namespace)
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize(
    "slots", [("--report",), ("../escape",), ("debian13", "debian13"), ("void",)]
)
def test_slots_are_declared_identifiers(
    source: Path, tmp_path: Path, slots: tuple[str, ...]
) -> None:
    """Options cannot be smuggled through the requested slot list."""
    with pytest.raises(ValueError, match="slots"):
        ci.run_ci(source, tmp_path / "output", "run-1", slots=slots)


@pytest.mark.parametrize(
    "package", ["--allow-unauthenticated", "a;touch evil", "$(id)", "/tmp/pkg", "x\ny"]
)
def test_build_packages_are_tokens(source: Path, tmp_path: Path, package: str) -> None:
    """Untrusted build arguments cannot supply shell syntax or package-manager options."""
    write_config(source, minimal_yml(slot_options=f"    extra-packages: [{json.dumps(package)}]\n"))
    with pytest.raises(ValueError, match="plain package names"):
        ci.run_ci(source, tmp_path / "output", "run-1")


def test_fragments_are_rejected(source: Path, tmp_path: Path) -> None:
    """A trusted engine never builds a PR's Containerfile fragment."""
    directory = source / "tests" / "containers" / "fragments"
    directory.mkdir()
    (directory / "Containerfile.debian13").write_text("RUN false\n")
    with pytest.raises(ValueError, match="fragments"):
        ci.run_ci(source, tmp_path / "output", "run-1")


@pytest.mark.parametrize("component", ["matrix.yml", "containers"])
def test_config_symlinks_are_rejected(source: Path, tmp_path: Path, component: str) -> None:
    """Neither declarations nor their parent directories may redirect host reads."""
    path = source / "tests" / "containers"
    if component == "matrix.yml":
        path /= component
    destination = tmp_path / "redirected"
    path.rename(destination)
    path.symlink_to(destination)
    with pytest.raises(OSError):
        ci.run_ci(source, tmp_path / "output", "run-1")


def test_request_paths_and_parallelism_are_restricted(source: Path, tmp_path: Path) -> None:
    """Output must be new and separate; CI does not join developer parallel work."""
    output = tmp_path / "output"
    for repo, destination, jobs in [
        (Path("relative"), output, 1),
        (source, source / "output", 1),
        (source, output, 2),
        (source, source, 1),
    ]:
        with pytest.raises(ValueError):
            ci.run_ci(repo, destination, "run-1", jobs=jobs)


def test_ci_reuses_engine_with_separate_slot_outputs(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The normal report lifecycle consumes isolated outputs and trusted names."""
    text = minimal_yml().replace("image-prefix: t", "image-prefix: ../../untrusted")
    text = text.replace("  debian13:", "  debian13:\n  alpine:")
    write_config(source, text)
    monkeypatch.setattr(cli, "build_image", lambda *args, **kwargs: True)
    cleanup = Mock()
    monkeypatch.setattr(cli, "_teardown", cleanup)
    monkeypatch.setattr(cli.Jobserver, "from_environ", Mock(side_effect=AssertionError))
    outputs = []

    def execute(config, name, results, **kwargs):
        """Record the policy passed to the engine without invoking Podman."""
        assert config.ci and config.krun
        assert config.image_prefix == "ci-run-1"
        outputs.append(results)
        return runner.SlotResult(True, "5.0")

    monkeypatch.setattr(cli, "run_slot", execute)
    output = tmp_path / "output"
    assert ci.run_ci(source, output, "run-1", krun=True) == 0
    assert outputs == [output / "scratch" / name / "outputs" for name in ("debian13", "alpine")]
    assert json.loads((output / ci.REPORT_NAME).read_text())["state"] == "passed"
    cleanup.assert_called_once()


def test_ci_build_context_excludes_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host_podman: Path
) -> None:
    """Repository ignore files and source contents do not affect trusted image builds."""
    config = replace(load_fixture(tmp_path / "repo"), ci=True, image_prefix="ci-run-1")
    (config.repo_root / ".containerignore").write_text("*\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    invoke = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(runner.subprocess, "run", invoke)
    assert runner.build_image(config, "debian13", scratch)
    argv = invoke.call_args.args[0]
    assert argv[0] == str(host_podman)
    assert Path(argv[-1]) == scratch / "build-context"
    assert list(Path(argv[-1]).iterdir()) == []
    assert str(config.repo_root) not in argv


@pytest.mark.parametrize("booted", [False, True])
def test_ci_scripts_are_readonly_inputs(tmp_path: Path, booted: bool) -> None:
    """Only the selected slot's output directory is writable in its workload."""
    config = replace(load_fixture(tmp_path / "repo"), ci=True)
    outputs = tmp_path / "slot" / "outputs"
    outputs.mkdir(parents=True)
    runner._write_scripts(config, "debian13", outputs, "all", booted)
    inputs = outputs.parent / "inputs"
    argv = runner._run_argv(config, "debian13", outputs, boots_systemd=booted)
    assert f"{inputs}:{INPUTS_MOUNT}:ro,z" in argv
    assert f"{outputs}:{RESULTS_MOUNT}:rw,z" in argv
    assert not list(outputs.iterdir())
    assert f"{INPUTS_MOUNT}/inner-debian13.sh" in (inputs / "outer-debian13.sh").read_text()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "oversized", "invalid-utf8"])
def test_untrusted_result_files_are_bounded_regular_files(tmp_path: Path, kind: str) -> None:
    """Artifact collection cannot follow links, block on pipes, or read unlimited data."""
    path = tmp_path / "debian13.podman-version"
    if kind == "symlink":
        secret = tmp_path / "secret"
        secret.write_text("not a test result")
        path.symlink_to(secret)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    elif kind == "oversized":
        path.write_text("x" * 17)
    else:
        path.write_bytes(b"\xff")
    with pytest.raises((OSError, UnicodeError)):
        read_regular(path, limit=16)
    if kind != "oversized":
        assert runner._observed_version("debian13", tmp_path) == "?"


def test_sigterm_finalizes_report_and_restores_handler(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Supervised termination uses the normal interruption and teardown path."""
    previous = signal.getsignal(signal.SIGTERM)

    def interrupted(*args, **kwargs):
        """Deliver the installed handler without signalling pytest itself."""
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        handler(signal.SIGTERM, None)

    monkeypatch.setattr(cli, "_walk_matrix", interrupted)
    cleanup = Mock()
    monkeypatch.setattr(cli, "_teardown", cleanup)
    output = tmp_path / "output"
    assert ci.run_ci(source, output, "run-1") == 130
    assert signal.getsignal(signal.SIGTERM) == previous
    assert json.loads((output / ci.REPORT_NAME).read_text())["state"] == "cancelled"
    cleanup.assert_called_once()


def test_cleanup_uses_only_trusted_namespace(
    monkeypatch: pytest.MonkeyPatch, host_podman: Path
) -> None:
    """Crash cleanup never discovers a container name from the tested source."""
    invoke = Mock(return_value=SimpleNamespace(stdout="one\ntwo\n", returncode=0))
    monkeypatch.setattr(runner.subprocess, "run", invoke)
    assert ci.cleanup_ci("run-1") == 2
    listing, removal = invoke.call_args_list
    assert f"label={OWNERSHIP_LABEL}=ci-run-1" in listing.args[0]
    assert removal.args[0] == [str(host_podman), "rm", "-f", "-t", "0", "one", "two"]
    assert listing.kwargs["check"] and removal.kwargs["check"]


def test_cli_rejects_extra_flags(source: Path, tmp_path: Path) -> None:
    """The service-facing CLI cannot select an alternate config or output report."""
    with pytest.raises(SystemExit):
        ci.main(["--config", str(source / "anything")])
    assert ci.main(["--cleanup", "../escape"]) == 2


def test_cli_dispatches_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker can request cleanup through the isolated module entry point."""
    cleanup = Mock()
    monkeypatch.setattr(ci, "cleanup_ci", cleanup)
    assert ci.main(["--cleanup", "run-1"]) == 0
    cleanup.assert_called_once_with("run-1")


def test_ci_keeps_repository_commands_inside_generated_workload(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Repository phases remain shell programs, but never become host shellouts."""
    marker = tmp_path / "must-not-exist"
    phase = f"printf untrusted > {marker}"
    write_config(source, minimal_yml().replace("pytest: tests/ -v", f"run: [{json.dumps(phase)}]"))
    config, _ = ci._prepare(source, tmp_path / "output", "run-1", (), False, 1)
    invoke = Mock(side_effect=AssertionError("host execution"))
    monkeypatch.setattr(runner.subprocess, "run", invoke)
    outputs = tmp_path / "slot" / "outputs"
    outputs.mkdir(parents=True)
    runner._write_scripts(config, "debian13", outputs, "all", False)
    script = (outputs.parent / "inputs" / "inner-debian13.sh").read_text()
    assert phase in script
    assert "uv sync --locked --active" in script
    assert not marker.exists()
    invoke.assert_not_called()


def test_cli_runs_the_selected_immutable_checkout(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The module interface forwards only its typed fixed options."""
    execute = Mock(return_value=1)
    monkeypatch.setattr(ci, "run_ci", execute)
    output = tmp_path / "output"
    assert (
        ci.main(
            [
                "--repo",
                str(source),
                "--output",
                str(output),
                "--namespace",
                "run-1",
                "--krun",
                "--",
                "debian13",
            ]
        )
        == 1
    )
    execute.assert_called_once_with(source, output, "run-1", slots=("debian13",), krun=True, jobs=1)
