<!--
SPDX-FileCopyrightText: 2026 Jiri Vyskocil
SPDX-License-Identifier: Apache-2.0
-->

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://terok-ai.github.io/terok/terok-logo-w.svg">
    <img src="https://terok-ai.github.io/terok/terok-logo-b.svg" alt="terok-util" width="120">
  </picture>
</p>

# terok-util

[![PyPI](https://img.shields.io/pypi/v/terok-util)](https://pypi.org/project/terok-util/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![REUSE status](https://api.reuse.software/badge/github.com/terok-ai/terok-util)](https://api.reuse.software/info/github.com/terok-ai/terok-util)

Shared utility library for the [`terok-*`](https://github.com/terok-ai)
sibling packages.

`terok-util` sits at the bottom of the terok dependency chain: every
sibling package depends on it, and it depends on nothing else in the
ecosystem. It collects the small set of cross-cutting bits that would
otherwise be duplicated (or quietly diverge) across
[`terok-shield`](https://github.com/terok-ai/terok-shield),
[`terok-clearance`](https://github.com/terok-ai/terok-clearance),
[`terok-sandbox`](https://github.com/terok-ai/terok-sandbox),
[`terok-executor`](https://github.com/terok-ai/terok-executor), and
[`terok`](https://github.com/terok-ai/terok).

## What's in the box

| Module | Use case |
|---|---|
| `cli_types` | `CommandDef` / `ArgDef` / `CommandTree` — argparse-driven CLI registry types used by every sibling that exposes a CLI tree. |
| `fs` | `ensure_dir`, `ensure_dir_writable`, `write_sensitive_file` (atomic `O_CREAT \| O_EXCL` 0o600 writer). |
| `paths` | `namespace_state_dir`, `namespace_config_dir`, `namespace_runtime_dir` — XDG-aware path resolution for a per-namespace deployment. |
| `config_stack` | `ConfigStack` + `deep_merge` — layered round-trip YAML config merge engine. |
| `security` | `sanitize_tty` — strips C0 / C1 / ANSI sequences from untrusted strings before rendering to the operator's terminal (CWE-150 mitigation). |
| `podman` | `podman_userns_args` — rootless `--userns=keep-id:uid=1000,gid=1000` builder. |

## Installation

```bash
pip install terok-util
```

The package is published as a Python wheel; siblings pin to a specific
GitHub-release wheel URL via `pyproject.toml`.

## Convention

The rule for what belongs here: **if two or more terok-`*` packages
need it, it lives in `terok-util`.** Single-package helpers stay in
the package that owns them. The `__all__` declaration in
`src/terok_util/__init__.py` is the contract — symbols listed there
are stable across minor releases.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Matrix reporting

`terok-matrix --report report.json [slots...]` writes an atomic JSON snapshot
alongside the normal terminal output. It updates after build and test transitions,
and retains completed verdicts if the matrix is interrupted. The destination is
independent of the engine's temporary workspace.

The snapshot has `schema_version: 1`, matrix `state`, `exit_code`, `error`, elapsed
`duration` in seconds, and a `slots` object keyed by slot name. Each slot records
its `state`, `reason`, `observed` version, optional suspected `network_hint`,
`duration`, and within-slot `skips`. Slot states are `pending`, `building`, `built`,
`testing`, `passed`, `failed`, `build_failed`, `skipped`, `cancelled`, or `error`.
A build-only run leaves successful slots `built`, not `passed`.

Consumers can poll this file without parsing terminal output. SIGTERM and Ctrl-C
finalize the report; SIGKILL cannot, so the supervising process must report that
interruption. Configuration errors before execution may leave no report.

## Restricted matrix execution for CI

`terok-matrix-ci` runs a disposable checkout with a separately installed engine.
It does not change `terok-matrix` or the editable development workflow. A worker
should invoke its trusted interpreter with isolated Python imports:

```bash
/opt/matrix-worker/bin/python -I -m terok_util.matrix.ci \
    --repo /srv/matrix/checkouts/approved-sha \
    --output /srv/matrix/runs/new-run \
    --namespace run-123 --krun -- debian13 fedora44
```

The output directory must not exist. Its parent must already exist outside the
checkout. `report.json` uses the normal report format. CI runs slots serially;
`--jobs` accepts only `1`. Namespace identifiers contain 1–48 lowercase
alphanumeric/hyphen characters and must start with an alphanumeric character.

CI rejects repository Containerfile fragments, symlinked declarations, YAML aliases,
non-string text fields and unsafe package names. YAML nesting and event counts are
bounded before object construction. It builds packaged templates with an empty build context and
replaces the declared image prefix with the worker's run namespace. Test phases
and dependency installation still execute inside the workload. Each slot gets
readonly generated inputs and its own writable outputs. Result collection rejects
symlinks, special files, invalid UTF-8 and oversized files. Workload output is
streamed in bounded chunks even when it contains no newlines.

After stopping an engine process group, a supervisor can remove that run's
containers without consulting the checkout:

```bash
/opt/matrix-worker/bin/python -I -m terok_util.matrix.ci --cleanup run-123
```

The caller remains responsible for immutable approved commits, credentials,
network restrictions, deadlines and resource limits. `--krun` isolates test
kernels; trusted image builds and image probes still use the host's default
runtime. Privileged Podman execution is not a hostile-code security boundary.
